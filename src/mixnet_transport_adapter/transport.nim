import chronicles, chronos, options, sequtils, std/sysrand, strformat, strutils, tables
import
  libp2p/[multiaddress, stream/connection, transports/transport, upgrademngrs/upgrade]
import logical_connection
import
  ../[
    config, curve25519, fragmentation, mix_node, serialization, sphinx, tag_manager,
    utils,
  ]

type MixnetTransportAdapter* = ref object of Transport
  mixNodeInfo: MixNodeInfo
  pubNodeInfo: Table[PeerId, MixPubInfo]
  transport: Transport
  tagManager: TagManager

proc isMixNode(peerId: PeerId, pubNodeInfo: Table[PeerId, MixPubInfo]): bool =
  return peerId in pubNodeInfo

proc loadMixNodeInfo*(index: int): MixNodeInfo {.raises: [].} =
  let mixNodeInfoOpt = readMixNodeInfoFromFile(index)
  assert mixNodeInfoOpt.isSome, "Failed to load node info from file."
  return mixNodeInfoOpt.get()

proc loadAllButIndexMixPubInfo*(
    index, numNodes: int
): Table[PeerId, MixPubInfo] {.raises: [].} =
  var pubInfoTable = initTable[PeerId, MixPubInfo]()
  for i in 0 ..< numNodes:
    if i != index:
      let pubInfoOpt = readMixPubInfoFromFile(i)
      if pubInfoOpt.isSome:
        let pubInfo = pubInfoOpt.get()
        let (multiAddr, _, _) = getMixPubInfo(pubInfo)
        let peerId = getPeerIdFromMultiAddr(multiAddr)
        pubInfoTable[peerId] = pubInfo
  return pubInfoTable

# ToDo: Change to a more secure random number generator for production.
proc cryptoRandomInt(max: int): int =
  var bytes: array[8, byte]
  discard urandom(bytes)
  let value = cast[uint64](bytes)
  result = int(value mod uint64(max))

method sendThroughMixnet*(
    self: MixnetTransportAdapter, mixMsg: seq[byte], destination: MultiAddress
): Future[void] {.base, async.} =
  let (multiAddr, _, _, _, _) = getMixNodeInfo(self.mixNodeInfo)
  let peerID = getPeerIdFromMultiAddr(multiAddr)
  let paddedMsg = padMessage(mixMsg, peerID)

  var multiAddrs: seq[string] = @[]
  var publicKeys: seq[FieldElement] = @[]
  var hop: seq[Hop] = @[]
  var delay: seq[seq[byte]] = @[]

  let numMixNodes = self.pubNodeInfo.len
  assert numMixNodes > 0, "No public mix nodes available."

  var pubNodeInfoKeys = toSeq(self.pubNodeInfo.keys)
  var randPeerId: PeerId
  var availableIndices = toSeq(0 ..< numMixNodes)
  for i in 0 ..< L:
    if i == L - 1:
      randPeerId = PeerId.init(($destination).split("/mix/")[1]).value()
    else:
      let randomIndexPosition = cryptoRandomInt(availableIndices.len)
      let selectedIndex = availableIndices[randomIndexPosition]
      randPeerId = pubNodeInfoKeys[selectedIndex]
      availableIndices.del(randomIndexPosition)

    let (multiAddr, mixPubKey, _) =
      getMixPubInfo(self.pubNodeInfo.getOrDefault(randPeerId))
    multiAddrs.add(multiAddr)
    publicKeys.add(mixPubKey)
    hop.add(initHop(multiAddrToBytes(multiAddr)))

    let delayMilliSec = cryptoRandomInt(3)
    delay.add(uint16ToBytes(uint16(delayMilliSec)))

  # Wrap in Sphinx packet
  let serializedMsg = serializeMessageChunk(paddedMsg)
  let sphinxPacket =
    wrapInSphinxPacket(initMessage(serializedMsg), publicKeys, delay, hop)

  # Send the wrapped message to the first mix node in the selected path
  let parts = multiAddrs[0].split("/mix/")
  if parts.len != 2:
    trace "Invalid multiaddress format: ", parts
    return

  let firstMixAddr = MultiAddress.init(parts[0]).value()
  let firstMixPeerId = PeerId.init(parts[1]).value()
  let tcpConn = await self.transport.dial("", firstMixAddr, Opt.some(firstMixPeerId))
  await tcpConn.writeLp(sphinxPacket)
  await sleepAsync(milliseconds(100))
  await tcpConn.close()

method log*(self: MixnetTransportAdapter): string {.gcsafe.} =
  "<MixnetTransportAdapter>"

proc handlesDial(address: MultiAddress): bool {.gcsafe.} =
  return TCPMix.match(address)

proc handlesStart(address: MultiAddress): bool {.gcsafe.} =
  return TcpMix.match(address)

method start*(self: MixnetTransportAdapter, mixAddrs: seq[MultiAddress]) {.async.} =
  echo "# Start"
  var tcpAddrs: seq[MultiAddress]
  for i, ma in mixAddrs:
    if not handlesStart(ma):
      warn "Invalid address detected, skipping!", address = ma
      continue
    let tcpAddress = MultiAddress.init(($ma).split("/mix/")[0]).value()
    tcpAddrs.add(tcpAddress)

  if len(tcpAddrs) != 0 and len(mixAddrs) != 0:
    await procCall Transport(self).start(mixAddrs)
    await self.transport.start(tcpAddrs)
  else:
    raise (ref transport.TransportError)(
      msg: "Mix transport couldn't start, no supported addr was provided."
    )

method stop*(self: MixnetTransportAdapter) {.async.} =
  echo "# Stop"
  await self.transport.stop()
  await procCall self.Transport.stop()

proc acceptWithMixnet(self: MixnetTransportAdapter): Future[Connection] {.async.} =
  echo "> MixnetTransportAdapter::accept"
  let conn = await self.transport.accept()
  echo "< MixnetTransportAdapter::accept"
  let remotePeerId = conn.peerID
  if isMixNode(remotePeerId, self.pubNodeInfo):
    while true:
      var receivedBytes = await conn.readLp(packetSize)

      if receivedBytes.len == 0:
        break # No data, end of stream

      # Process the packet
      let
        (multiAddr, _, mixPrivKey, _, _) = getMixNodeInfo(self.mixNodeInfo)
        (nextHop, delay, processedPkt, status) =
          processSphinxPacket(receivedBytes, mixPrivKey, self.tagManager)

      case status
      of Success:
        if (nextHop == Hop()) and (delay == @[]):
          # This is the exit node, forward to local protocol instance
          let
            msgChunk = deserializeMessageChunk(processedPkt)
            unpaddedMsg = unpadMessage(msgChunk)
          echo "Receiver: ", multiAddr
          echo "Message received: ", cast[string](unpaddedMsg)
        else:
          echo "Intermediate: ", multiAddr
          # Add delay
          let delayMillis = (delay[0].int shl 8) or delay[1].int
          await sleepAsync(milliseconds(delayMillis))

          # Forward to next hop
          let
            nextHopBytes = getHop(nextHop)
            fullAddrStr = bytesToMultiAddr(nextHopBytes)
            parts = fullAddrStr.split("/mix/")
          if parts.len != 2:
            raise (ref ValueError)(msg: "Invalid multiaddress format: " & $parts)

          let
            nextMixAddr = MultiAddress.init(parts[0]).value()
            nextMixPeerId = PeerId.init(parts[1]).value()
            tcpConn =
              await self.transport.dial("", nextMixAddr, Opt.some(nextMixPeerId))
          await tcpConn.writeLp(processedPkt)
          await tcpConn.close()
      of Duplicate:
        discard
      of InvalidMAC:
        discard
      of InvalidPoW:
        discard

    # Close the current connection after processing
    await conn.close()
  return conn

method accept*(self: MixnetTransportAdapter): Future[Connection] {.gcsafe.} =
  echo "# Accept"
  self.acceptWithMixnet()

method dialWithMixnet*(
    self: MixnetTransportAdapter,
    hostname: string,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
): Future[Connection] {.base, async.} =
  echo "> MixnetTransportAdapter::dialWithMixnet1 - ", $peerId
  if not handlesDial(address):
    raise newException(LPError, fmt"Address not supported: {address}")
  var sendFunc = proc(
      msg: seq[byte], destination: MultiAddress
  ): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
    try:
      await self.sendThroughMixnet(msg, destination)
    except CatchableError as e:
      echo "Error during execution of sendThroughMixnet: ", e.msg
      # TODO: handle error
    return

  MixLogicalConnection.new(address, sendFunc)

method dial*(
    self: MixnetTransportAdapter,
    hostname: string,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
): Future[Connection] {.gcsafe.} =
  echo "> MixnetTransportAdapter::dial1"
  self.dialWithMixnet(hostname, address, peerId)

method handles*(self: MixnetTransportAdapter, address: MultiAddress): bool {.gcsafe.} =
  echo "# Handles"
  if procCall Transport(self).handles(address):
    return handlesDial(address) or handlesStart(address)

proc new*(
    T: typedesc[MixnetTransportAdapter],
    transport: Transport,
    upgrade: Upgrade,
    index, numNodes: int,
): MixnetTransportAdapter {.raises: [].} =
  let
    mixNodeInfo = loadMixNodeInfo(index)
    pubNodeInfo = loadAllButIndexMixPubInfo(index, numNodes)
    tagManager = initTagManager()
  return T(
    mixNodeInfo: mixNodeInfo,
    pubNodeInfo: pubNodeInfo,
    transport: transport,
    tagManager: tagManager,
    upgrader: upgrade,
  )
