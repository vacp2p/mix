import chronos
import config, curve25519, fragmentation, mix_node, sequtils, serialization,
    sphinx, tag_manager, utils
import libp2p
import libp2p/[protocols/ping, protocols/protocol, stream/connection,
    stream/lpstream, switch]
import std/sysrand, strutils

const MixProtocolID* = "/mix/proto/1.0.0"

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

proc isMixNode(peerId: PeerId, pubNodeInfo: Table[PeerId, MixPubInfo]): bool =
  return peerId in pubNodeInfo

# ToDo: Change to a more secure random number generator for production.
proc cryptoRandomInt(max: int): int =
  var bytes: array[8, byte]
  let value = cast[uint64](bytes)
  result = int(value mod uint64(max))

proc sendChunk(mixProto: MixProtocol, chunk: seq[byte]) {.async.} =
  var multiAddrs: seq[string] = @[]
  var publicKeys: seq[FieldElement] = @[]
  var hop: seq[Hop] = @[]
  var delay: seq[seq[byte]] = @[]

  # Select L mix nodes at random
  let numMixNodes = mixProto.pubNodeInfo.len
  assert numMixNodes > 0, "No public mix nodes available."

  var pubNodeInfoKeys = toSeq(mixProto.pubNodeInfo.keys)
  for _ in 0..<L:
    let randomIndex = cryptoRandomInt(numMixNodes)
    let randPeerId = pubNodeInfoKeys[randomIndex]

    # Extract multiaddress, mix public key, and hop
    let (multiAddr, mixPubKey, _) = getMixPubInfo(mixProto.pubNodeInfo[randPeerId])
    multiAddrs.add(multiAddr)
    publicKeys.add(mixPubKey)
    hop.add(initHop(multiAddrToBytes(multiAddr)))

    # Compute delay
    let delayMilliSec = cryptoRandomInt(3)
    delay.add(uint16ToBytes(uint16(delayMilliSec)))

  # Wrap in Sphinx packet
  let sphinxPacket = wrapInSphinxPacket(initMessage(chunk), publicKeys, delay, hop)

  # Send the wrapped message to the first mix node in the selected path
  let firstMixNode = multiAddrs[0]
  var nextHopConn: Connection
  try:
    nextHopConn = await mixProto.switch.dial(getPeerIdFromMultiAddr(
        firstMixNode), @[MultiAddress.init(firstMixNode).get()], @[MixProtocolID])
    await nextHopConn.writeLp(sphinxPacket)
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
    let (_, _, mixPrivKey, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)
    let (nextHop, delay, processedPkt, status) = processSphinxPacket(
        receivedBytes, mixPrivKey, mixProto.tagManager)

    case status:
    of Success:
      if (nextHop == Hop()) and (delay == @[]):
        # This is the exit node, forward to local ping protocol instance
        try:
          let peerInfo = mixProto.switch.peerInfo
          let pingStream = await mixProto.switch.dial(peerInfo.peerId,
              peerInfo.addrs, PingCodec)
          await pingStream.writeLP(processedPkt)
          await pingStream.close()
        except CatchableError as e:
          echo "Failed to forward to ping protocol: ", e.msg
      else:
        # Add delay
        let delayMillis = (delay[0].int shl 8) or delay[1].int
        await sleepAsync(milliseconds(delayMillis))

        # Forward to next hop
        let nextHopBytes = getHop(nextHop)
        let fullAddrStr = bytesToMultiAddr(nextHopBytes)
        let parts = fullAddrStr.split("/mix/")
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

proc handlePingInstanceConnection(mixProto: MixProtocol,
    conn: Connection) {.async.} =
  var message: seq[byte] = @[]
  while true:
    var receivedBytes = await conn.readLp(1024)
    if receivedBytes.len == 0:
      break # No more data, end of stream
    message.add(receivedBytes)

  if message.len == 0:
    await conn.close()
    return

  # Pad and chunk the incoming message
  let (multiAddr, _, _, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)
  let peerID = getPeerIdFromMultiAddr(multiAddr)
  let chunks = padAndChunkMessage(message, peerID)

  # Wrap and send each chunk
  for chunk in chunks:
    await sendChunk(mixProto, serializeMessageChunk(chunk))

  # Close the connection after processing
  await conn.close()

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

  proc handle(conn: Connection, proto: string) {.async.} =
    let remotePeerId = conn.peerId
    if isMixNode(remotePeerId, pubNodeInfo):
      await handleMixNodeConnection(mixProto, conn)
    else:
      await handlePingInstanceConnection(mixProto, conn)

  mixProto.init()
  mixProto.codecs = @[MixProtocolID]
  mixProto.handler = handle

  return mixProto
