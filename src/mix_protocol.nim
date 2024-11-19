import chronos
import config, curve25519, fragmentation, mix_message, mix_node, sequtils,
    serialization, sphinx, tag_manager, utils
import libp2p
import libp2p/[protocols/ping, protocols/protocol, stream/connection,
    stream/lpstream, switch]
import std/sysrand, strutils

const MixProtocolID* = "/mix/1.0.0"

type
  MixProtocol* = ref object of LPProtocol
    mixNodeInfo: MixNodeInfo
    pubNodeInfo: Table[PeerId, MixPubInfo]
    switch: Switch
    tagManager: TagManager

proc loadMixNodeInfo*(index: int): MixNodeInfo =
  let mixNodeInfoOpt = readMixNodeInfoFromFile(index)
  assert mixNodeInfoOpt.isSome, "Failed to load node info from file."
  return mixNodeInfoOpt.get()

proc loadAllButIndexMixPubInfo*(index, numNodes: int): Table[PeerId, MixPubInfo] =
  var pubInfoTable = initTable[PeerId, MixPubInfo]()
  for i in 0..<numNodes:
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

proc sendMessage(mixProto: MixProtocol, message: seq[byte],
    destMultiAddr: MultiAddress, destPeerId: PeerId) {.async.} =
  var multiAddrs: seq[string] = @[]
  var publicKeys: seq[FieldElement] = @[]
  var hop: seq[Hop] = @[]
  var delay: seq[seq[byte]] = @[]

  # Select L mix nodes at random
  let numMixNodes = mixProto.pubNodeInfo.len
  assert numMixNodes > 0, "No public mix nodes available."

  var pubNodeInfoKeys = toSeq(mixProto.pubNodeInfo.keys)
  var randPeerId: PeerId
  var availableIndices = toSeq(0..<numMixNodes)
  for i in 0..<L:
    if i == L - 1:
      randPeerId = destPeerId
    else:
      let randomIndexPosition = cryptoRandomInt(availableIndices.len)
      let selectedIndex = availableIndices[randomIndexPosition]
      randPeerId = pubNodeInfoKeys[selectedIndex]
      availableIndices.del(randomIndexPosition)

    # Extract multiaddress, mix public key, and hop
    let (multiAddr, mixPubKey, _) = getMixPubInfo(mixProto.pubNodeInfo[randPeerId])
    multiAddrs.add(multiAddr)
    publicKeys.add(mixPubKey)
    hop.add(initHop(multiAddrToBytes(multiAddr)))

    # Compute delay
    let delayMilliSec = cryptoRandomInt(3)
    delay.add(uint16ToBytes(uint16(delayMilliSec)))

  # Wrap in Sphinx packet
  let sphinxPacket = wrapInSphinxPacket(initMessage(message), publicKeys, delay, hop)

  # Send the wrapped message to the first mix node in the selected path
  let firstMixNode = multiAddrs[0]
  var nextHopConn: Connection
  try:
    nextHopConn = await mixProto.switch.dial(getPeerIdFromMultiAddr(
        firstMixNode), @[MultiAddress.init(firstMixNode.split("/p2p/")[0]).get()], @[MixProtocolID])
    await nextHopConn.writeLp(sphinxPacket)
    await sleepAsync(milliseconds(100))
  except CatchableError as e:
    echo "Failed to send message to next hop: ", e.msg
  finally:
    if not nextHopConn.isNil:
      await nextHopConn.close()

proc handleMixNodeConnection(mixProto: MixProtocol,
    conn: Connection) {.async.} =
  while true:
    var receivedBytes = await conn.readLp(packetSize)

    if receivedBytes.len == 0:
      break # No data, end of stream

    # Process the packet
    let (multiAddr, _, mixPrivKey, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)
    let (nextHop, delay, processedPkt, status) = processSphinxPacket(
        receivedBytes, mixPrivKey, mixProto.tagManager)

    case status:
    of Success:
      if (nextHop == Hop()) and (delay == @[]):
        # This is the exit node, forward to local protocol instance
        let msgChunk = deserializeMessageChunk(processedPkt)
        let unpaddedMsg = unpadMessage(msgChunk)
        let mixMsg = deserializeMixMessage(unpaddedMsg)
        let (message, protocol) = getMixMessage(mixMsg)
        echo "Receiver: ", multiAddr
        echo "Message received: ", cast[string](message)
        case protocol:
        of Ping:
          try:
            let peerInfo = mixProto.switch.peerInfo
            let pingStream = await mixProto.switch.dial(peerInfo.peerId,
              peerInfo.addrs, PingCodec)
            await pingStream.writeLP(cast[seq[byte]](message))
            await pingStream.close()
          except CatchableError as e:
            echo "Failed to forward to ping protocol: ", e.msg
        of GossipSub:
          discard
        of OtherProtocol:
          discard
      else:
        echo "Intermediate: ", multiAddr
        # Add delay
        let delayMillis = (delay[0].int shl 8) or delay[1].int
        await sleepAsync(milliseconds(delayMillis))

        # Forward to next hop
        let nextHopBytes = getHop(nextHop)
        let fullAddrStr = bytesToMultiAddr(nextHopBytes)
        let parts = fullAddrStr.split("/p2p/")
        if parts.len != 2:
          echo "Invalid multiaddress format: ", fullAddrStr
          return

        let locationAddrStr = parts[0]
        let peerIdStr = parts[1]

        # Create MultiAddress and PeerId
        let locationAddrRes = MultiAddress.init(locationAddrStr)
        if locationAddrRes.isErr:
          echo "Failed to parse location multiaddress: ", locationAddrStr
          return
        let locationAddr = locationAddrRes.get()

        let peerIdRes = PeerId.init(peerIdStr)
        if peerIdRes.isErr:
          echo "Failed to parse PeerId: ", peerIdStr
          return
        let peerId = peerIdRes.get()

        var nextHopConn: Connection
        try:
          nextHopConn = await mixProto.switch.dial(peerId, @[locationAddr], MixProtocolID)
          await nextHopConn.writeLp(processedPkt)
        except CatchableError as e:
          echo "Failed to dial next hop: ", e.msg
        finally:
          if not nextHopConn.isNil:
            await nextHopConn.close()
    of Duplicate:
      discard
    of InvalidMAC:
      discard
    of InvalidPoW:
      discard

  # Close the current connection after processing
  await conn.close()

proc anonymizeLocalProtocolSend*(mixProto: MixProtocol,
    mixMsg: seq[byte], destMultiAddr: MultiAddress, destPeerId: PeerId) {.async.} =
  # Pad the incoming message
  # ToDo: Split large messages
  let (multiAddr, _, _, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)
  let peerID = getPeerIdFromMultiAddr(multiAddr)
  let paddedMsg = padMessage(mixMsg, peerID)

  echo "Sender: ", multiAddr
  echo "Message sent: ", cast[string](mixMsg)
  await sendMessage(mixProto, serializeMessageChunk(paddedMsg), destMultiAddr, destPeerId)

proc new*(T: typedesc[MixProtocol], index, numNodes: int, switch: Switch): T =
  let mixNodeInfo = loadMixNodeInfo(index)
  let pubNodeInfo = loadAllButIndexMixPubInfo(index, numNodes)
  let tagManager = initTagManager()

  let mixProto = T(
    mixNodeInfo: mixNodeInfo,
    pubNodeInfo: pubNodeInfo,
    switch: switch,
    tagManager: tagManager
  )
  mixProto.init()
  return mixProto

method init*(mixProtocol: MixProtocol) {.gcsafe, raises: [].} =
  proc handle(conn: Connection, proto: string) {.async.} =
    await mixProtocol.handleMixNodeConnection(conn)

  mixProtocol.codecs = @[MixProtocolID]
  mixProtocol.handler = handle
