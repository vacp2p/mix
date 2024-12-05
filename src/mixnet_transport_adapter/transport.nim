import
  chronicles,
  chronos,
  options,
  results,
  sequtils,
  std/sysrand,
  strformat,
  strutils,
  tables
import
  libp2p/[multiaddress, stream/connection, transports/transport, upgrademngrs/upgrade]
import exit_connection, logical_connection, physical_connection, protocol
import
  ../[
    config, curve25519, fragmentation, mix_message, mix_node, serialization, sphinx,
    tag_manager, utils,
  ]

logScope:
  topics = "libp2p mixtransport"

type
  MixnetTransportAdapter* = ref object of Transport
    mixNodeInfo: MixNodeInfo
    pubNodeInfo: Table[PeerId, MixPubInfo]
    transport: Transport
    tagManager: TagManager
    handler: ProtocolHandler

  MixnetTransportError* = object of CatchableError

proc loadMixNodeInfo*(index: int): Result[MixNodeInfo, string] {.raises: [].} =
  let mixNodeInfoOpt = readMixNodeInfoFromFile(index)
  if mixNodeInfoOpt.isSome:
    ok(mixNodeInfoOpt.get())
  else:
    err("Failed to load node info from file.")

proc loadAllButIndexMixPubInfo*(
    index, numNodes: int
): Table[PeerId, MixPubInfo] {.raises: [].} =
  var pubInfoTable = initTable[PeerId, MixPubInfo]()
  for i in 0 ..< numNodes:
    if i != index:
      let pubInfoOpt = readMixPubInfoFromFile(i)
      if pubInfoOpt.isSome:
        let
          pubInfo = pubInfoOpt.get()
          (multiAddr, _, _) = getMixPubInfo(pubInfo)
          peerId = getPeerIdFromMultiAddr(multiAddr)
        pubInfoTable[peerId] = pubInfo
  return pubInfoTable

# ToDo: Change to a more secure random number generator for production.
proc cryptoRandomInt(max: int): Result[int, string] =
  if max == 0:
    return err("Max cannot be zero.")
  var bytes: array[8, byte]
  discard urandom(bytes)
  let value = cast[uint64](bytes)
  return ok(int(value mod uint64(max)))

method sendThroughMixnet*(
    self: MixnetTransportAdapter,
    mixMsg: seq[byte],
    proto: ProtocolType,
    destination: MultiAddress,
): Future[void] {.base, async.} =
  let mixMsg = initMixMessage(mixMsg, proto)

  let serializedResult = serializeMixMessage(mixMsg)
  if serializedResult.isErr:
    error "Serialization failed", err = serializedResult.error
    return
  let serialized = serializedResult.get()

  let
    (multiAddr, _, _, _, _) = getMixNodeInfo(self.mixNodeInfo)
    peerID = getPeerIdFromMultiAddr(multiAddr)
    paddedMsg = padMessage(serialized, peerID)

  var
    multiAddrs: seq[string] = @[]
    publicKeys: seq[FieldElement] = @[]
    hop: seq[Hop] = @[]
    delay: seq[seq[byte]] = @[]

  let numMixNodes = self.pubNodeInfo.len
  if numMixNodes < L:
    error "No. of public mix nodes less than path length."
    return

  var
    pubNodeInfoKeys = toSeq(self.pubNodeInfo.keys)
    randPeerId: PeerId
    availableIndices = toSeq(0 ..< numMixNodes)
  for i in 0 ..< L:
    if i == L - 1:
      randPeerId = PeerId.init(($destination).split("/mix/")[1]).valueOr:
        error "Failed to initialize PeerId", err = error
        return
    else:
      let cryptoRandomIntResult = cryptoRandomInt(availableIndices.len)
      if cryptoRandomIntResult.isErr:
        error "Failed to generate random number", err = cryptoRandomIntResult.error
        return
      let
        randomIndexPosition = cryptoRandomIntResult.value
        selectedIndex = availableIndices[randomIndexPosition]
      randPeerId = pubNodeInfoKeys[selectedIndex]
      availableIndices.del(randomIndexPosition)

    let (multiAddr, mixPubKey, _) =
      getMixPubInfo(self.pubNodeInfo.getOrDefault(randPeerId))
    multiAddrs.add(multiAddr)
    publicKeys.add(mixPubKey)
    hop.add(initHop(multiAddrToBytes(multiAddr)))

    let cryptoRandomIntResult = cryptoRandomInt(5)
    if cryptoRandomIntResult.isErr:
      error "Failed to generate random number", err = cryptoRandomIntResult.error
      return
    let delayMilliSec = cryptoRandomIntResult.value
    delay.add(uint16ToBytes(uint16(delayMilliSec)))

  # Wrap in Sphinx packet
  let
    serializedMsg = serializeMessageChunk(paddedMsg)
    sphinxPacket =
      wrapInSphinxPacket(initMessage(serializedMsg), publicKeys, delay, hop)

  # Send the wrapped message to the first mix node in the selected path
  let parts = multiAddrs[0].split("/mix/")
  if parts.len != 2:
    error "Invalid multiaddress format", parts = parts
    return

  let firstMixAddr = MultiAddress.init(multiAddrs[0]).valueOr:
    error "Failed to initialize MultiAddress", err = error
    return

  let firstMixPeerId = PeerId.init(parts[1]).valueOr:
    error "Failed to initialize PeerId", err = error
    return

  try:
    let mixConn = await self.dial("", firstMixAddr, Opt.some(firstMixPeerId))
    await mixConn.writeLp(getHop(hop[0]))
    await mixConn.writeLp(sphinxPacket)
    await sleepAsync(milliseconds(10))
    await mixConn.close()
  except CatchableError as e:
    error "Failed to send through mixnet",
      err = e.msg, address = $firstMixAddr, peerId = $firstMixPeerId

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
  var acceptedConn: Connection
  echo "> MixnetTransportAdapter::accept"
  let
    conn = await self.transport.accept()
    hopBytes = await conn.readLp(addrSize)
    multiAddr = bytesToMultiAddr(hopBytes)

  if isNodeMultiaddress(self.mixNodeInfo, multiAddr):
    var receivedBytes = await conn.readLp(packetSize)

    if receivedBytes.len == 0:
      error "End of stream"
      return

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

        let deserializedResult = deserializeMixMessage(unpaddedMsg)
        if deserializedResult.isErr:
          error "Deserialization failed", err = deserializedResult.error
          return
        let
          mixMsg = deserializedResult.get()
          (message, protocol) = getMixMessage(mixMsg)
          exitConn = MixExitConnection.new(message)
        await self.handler(exitConn, protocol)
        echo "Receiver: ", multiAddr
        echo "Message received: ", message
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
          error "Invalid multiaddress format", parts = parts
          return

        let nextMixAddr = MultiAddress.init(fullAddrStr).valueOr:
          error "Failed to initialize MultiAddress", err = error
          return

        let nextMixPeerId = PeerId.init(parts[1]).valueOr:
          error "Failed to initialize PeerId", err = error
          return

        try:
          let mixConn = await self.dial("", nextMixAddr, Opt.some(nextMixPeerId))
          await mixConn.writeLp(nextHopBytes)
          await mixConn.writeLp(processedPkt)
          await sleepAsync(milliseconds(10))
          #await mixConn.close()
        except CatchableError as e:
          error "Failed to send through mixnet",
            err = e.msg, address = $nextMixAddr, peerId = $nextMixPeerId
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

method dialMixPhysicalConn*(
    self: MixnetTransportAdapter,
    hostname: string,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
): Future[Connection] {.base, async.} =
  echo "> MixnetTransportAdapter::dialMixPhysicalConn - ", $peerId
  if not handlesDial(address):
    raise newException(LPError, fmt"Address not supported: {address}")

  let parts = ($address).split("/mix/")

  let tcpAddr = MultiAddress.init(parts[0]).valueOr:
    error "Failed to initialize MultiAddress", err = error
    return

  let connection = await self.transport.dial("", tcpAddr, peerId)

  MixPhysicalConnection.new(connection, Opt.some(address), peerId)

method dialMixLogicalConn*(
    self: MixnetTransportAdapter,
    hostname: string,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
    proto: string,
): Future[Connection] {.base, async.} =
  echo "> MixnetTransportAdapter::dialMixLogicalConn - ", $peerId
  if not handlesDial(address):
    raise newException(LPError, fmt"Address not supported: {address}")
  var sendFunc = proc(
      msg: seq[byte], proto: ProtocolType, destination: MultiAddress
  ): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
    try:
      await self.sendThroughMixnet(msg, proto, destination)
    except CatchableError as e:
      echo "Error during execution of sendThroughMixnet: ", e.msg
      # TODO: handle error
    return

  MixLogicalConnection.new(address, protocolFromString(proto), sendFunc)

method dialWithProto*(
    self: MixnetTransportAdapter,
    hostname: string,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
    proto: Opt[string] = Opt.none(string),
): Future[Connection] {.gcsafe, raises: [].} =
  echo "> MixnetTransportAdapter::dialWithProto"
  if proto.isSome:
    self.dialMixLogicalConn(hostname, address, peerId, proto.get())
  else:
    self.dialMixPhysicalConn(hostname, address, peerId)

method dial*(
    self: MixnetTransportAdapter,
    hostname: string,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
): Future[Connection] {.gcsafe.} =
  echo "> MixnetTransportAdapter::dial"
  self.dialWithProto(hostname, address, peerId, Opt.none(string))

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
  let mixNodeInfoResult = loadMixNodeInfo(index)
  if mixNodeInfoResult.isErr:
    error "Failed to load mix node info", index = index
    return T()

  let
    mixNodeInfo = mixNodeInfoResult.value
    pubNodeInfo = loadAllButIndexMixPubInfo(index, numNodes)
    tagManager = initTagManager()
  return T(
    mixNodeInfo: mixNodeInfo,
    pubNodeInfo: pubNodeInfo,
    transport: transport,
    tagManager: tagManager,
    upgrader: upgrade,
  )

proc setCallback*(self: MixnetTransportAdapter, cb: ProtocolHandler) =
  self.handler = cb
