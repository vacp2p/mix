import chronicles, chronos, sequtils, strutils, os
import std/[strformat, sysrand]
import
  ./[
    config, curve25519, exit_connection, fragmentation, mix_message, mix_node, protocol,
    serialization, sphinx, tag_manager, utils,
  ]
import libp2p
import
  libp2p/
    [protocols/ping, protocols/protocol, stream/connection, stream/lpstream, switch]

const MixProtocolID* = "/mix/1.0.0"

# Possibly important for reply block
type MixProtocol* = ref object
  lpProto: LPProtocol
  mixNodeInfo: MixNodeInfo
  pubNodeInfo: Table[PeerId, MixPubInfo]
  switch: Switch
  tagManager: TagManager
  pHandler: ProtocolHandler

# TODO: use Path type for paths
# TODO: result errors should be enum variants that come with extractable data/message.
# TODO: investigate file-read time as a sneaky factor in benchmark discrpency
proc loadMixNodeInfo*(
    index: int, nodeFolderInfoPath: string = "./nodeInfo"
): Result[MixNodeInfo, string] =
  let readNode = readMixNodeInfoFromFile(index, nodeFolderInfoPath).valueOr:
    return err("Failed to load node info from file: " & error)
  ok(readNode)

proc loadAllButIndexMixPubInfo*(
    index, numNodes: int, pubInfoFolderPath: string = "./pubInfo"
): Result[Table[PeerId, MixPubInfo], string] =
  var pubInfoTable = initTable[PeerId, MixPubInfo]()
  for i in 0 ..< numNodes:
    if i != index:
      let pubInfo = readMixPubInfoFromFile(i, pubInfoFolderPath).valueOr:
        return err("Failed to load pub info from file: " & error)

      let (multiAddr, _, _) = getMixPubInfo(pubInfo)

      let peerId = getPeerIdFromMultiAddr(multiAddr).valueOr:
        return err("Failed to get peer id from multiaddress: " & error)

      pubInfoTable[peerId] = pubInfo
  return ok(pubInfoTable)

# ToDo: Change to a more secure random number generator for production.
proc cryptoRandomInt(max: int): Result[int, string] =
  if max == 0:
    return err("Max cannot be zero.")
  var bytes: array[8, byte]
  discard urandom(bytes)
  let value = cast[uint64](bytes)
  return ok(int(value mod uint64(max)))

proc handleExit(nextHop: Hop, delay: seq[byte], processedPkt: seq[byte], sender: ProtocolHandler) {.async: (raises: [CancelledError]).} = 
  # TODO: have an exit error enum
  if (nextHop != Hop()) or (delay != @[]):
    error "Next hop and delay must be empty"
    return

  # This is the exit node, forward to destination
  let msgChunk = deserializeMessageChunk(processedPkt).valueOr:
    error "Deserialization failed", err = error
    return

  let unpaddedMsg = unpadMessage(msgChunk).valueOr:
    error "Unpadding message failed", err = error
    return

  let deserializedResult = deserializeMixMessage(unpaddedMsg).valueOr:
    error "Deserialization failed", err = error
    return

  let
    exitConn = MixExitConnection.new(deserializedResult.message)
  trace "# Received: ", receiver = multiAddr, message = deserializedResult.message
  await sender(exitConn, deserializedResult.protocol)

  if exitConn != nil:
    try:
      await exitConn.close()
    except CatchableError as e:
      error "Failed to close exit connection: ", err = e.msg

  
proc handleSuccess(nextHop: Hop, delay: seq[byte], processedPkt: seq[byte], switch: Switch) {.async: (raises: [CancelledError]).} = 
  trace "# Intermediate: ", multiAddr = multiAddr
  # Add delay
  let delayMillis = (delay[0].int shl 8) or delay[1].int
  await sleepAsync(milliseconds(delayMillis))

  # Forward to next hop
  let nextHopBytes = getHop(nextHop)

  let fullAddrStr = bytesToMultiAddr(nextHopBytes).valueOr:
    error "Failed to convert bytes to multiaddress", err = error
    return

  let parts = fullAddrStr.split("/p2p/")
  if parts.len != 2:
    error "Invalid multiaddress format", parts = parts
    return

  let
    locationAddrStr = parts[0]
    peerIdStr = parts[1]

  # Create MultiAddress and PeerId
  let locationAddr = MultiAddress.init(locationAddrStr).valueOr:
    error "Failed to parse location multiaddress: ", err = error
    return

  let peerId = PeerId.init(peerIdStr).valueOr:
    error "Failed to initialize PeerId", err = error
    return

  var nextHopConn: Connection
  try:
    nextHopConn = await switch.dial(peerId, @[locationAddr], MixProtocolID)
    await nextHopConn.writeLp(processedPkt)
  except CatchableError as e:
    error "Failed to dial next hop: ", err = e.msg
  finally:
    if nextHopConn != nil:
      try:
        await nextHopConn.close()
      except CatchableError as e:
        error "Failed to close outgoing stream: ", err = e.msg

# TODO: This could use enum-dispatch to delegate to specific functions
proc handleMixNodeConnection(
    mixProto: MixProtocol, conn: Connection
) {.async: (raises: [CancelledError]).} =
  var receivedBytes: seq[byte]
  try:
    receivedBytes = await conn.readLp(packetSize)
  except Exception as e:
    error "Failed to read: ", err = e.msg
  finally:
    if conn != nil:
      try:
        await conn.close()
      except CatchableError as e:
        error "Failed to close incoming stream: ", err = e.msg

  if receivedBytes.len == 0:
    return # No data, end of stream

  # Process the packet
  let (multiAddr, _, mixPrivKey, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)

  # TODO: This should be a struct instead of a tuple
  let (nextHop, delay, processedPkt, status) = processSphinxPacket(receivedBytes, mixPrivKey, mixProto.tagManager).valueOr:
    error "Failed to process Sphinx packet", err = error
    return

  case status
  of Exit:
    await handleExit(nextHop, delay, processedPkt, mixProto.pHandler)
  of Intermediary:
    await handleSuccess(nextHop, delay, processedPkt, mixProto.switch)
  of Duplicate:
    discard
  of InvalidMAC:
    discard

proc anonymizeLocalProtocolSend*(
    mixProto: MixProtocol,
    # TODO: this should be a distinct message type
    msg: seq[byte],
    proto: ProtocolType,
    destMultiAddr: Option[MultiAddress],
    destPeerId: PeerId,
) {.async.} =
  # TODO: pass in the MixMessage struct instead of msg and proto
  let mixMsg = initMixMessage(msg, proto)

  # TODO?: ...or consider passing it in in serialized form?
  let serialized = serializeMixMessage(mixMsg).valueOr:
    error "Serialization failed", err = error
    return

  let (multiAddr, _, _, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)

  let peerId = getPeerIdFromMultiAddr(multiAddr).valueOr:
    error "Failed to get peer id from multiaddress", err = error
    return

  let paddedMsg = padMessage(serialized, peerID)

  trace "# Sent: ", sender = multiAddr, message = msg, dest = destMultiAddr

  # TODO: This should be a struct instead
  var
    multiAddrs: seq[string] = @[]
    publicKeys: seq[FieldElement] = @[]
    hop: seq[Hop] = @[]
    delay: seq[seq[byte]] = @[]

  # Select PATH_LEN mix nodes at random
  let numMixNodes = mixProto.pubNodeInfo.len
  if numMixNodes < PATH_LEN:
    error "No. of public mix nodes less than path length."
    return

  var
    pubNodeInfoKeys = toSeq(mixProto.pubNodeInfo.keys)
    randPeerId: PeerId
    availableIndices = toSeq(0 ..< numMixNodes)
  for i in 0 ..< PATH_LEN:
    let randomIndexPosition = cryptoRandomInt(availableIndices.len).valueOr:
      error "Failed to generate random number", err = error
      return
    let selectedIndex = availableIndices[randomIndexPosition]
    randPeerId = pubNodeInfoKeys[selectedIndex]
    availableIndices.del(randomIndexPosition)

    # Extract multiaddress, mix public key, and hop
    let (multiAddr, mixPubKey, _) =
      getMixPubInfo(mixProto.pubNodeInfo.getOrDefault(randPeerId))
    multiAddrs.add(multiAddr)
    publicKeys.add(mixPubKey)

    let multiAddrBytes = multiAddrToBytes(multiAddr).valueOr:
      error "Failed to convert multiaddress to bytes", err = error
      return

    hop.add(initHop(multiAddrBytes))

    # Compute delay
    let delayMilliSec = cryptoRandomInt(3).valueOr:
      error "Failed to generate random number", err = error
      return
    delay.add(uint16ToBytes(uint16(delayMilliSec)))

  let serializedRes = serializeMessageChunk(paddedMsg).valueOr:
    error "Failed to serialize padded message", err = error
    return

  # Wrap in Sphinx packet
  let sphinxPacket = wrapInSphinxPacket(
    initMessage(serializedRes), publicKeys, delay, hop
  ).valueOr:
    error "Failed to wrap in sphinx packet", err = error
    return

  # Send the wrapped message to the first mix node in the selected path
  let parts = multiAddrs[0].split("/p2p/")
  if parts.len != 2:
    error "Invalid multiaddress format", parts = parts
    return

  let firstMixAddr = MultiAddress.init(parts[0]).valueOr:
    error "Failed to initialize MultiAddress", err = error
    return

  let firstMixPeerId = PeerId.init(parts[1]).valueOr:
    error "Failed to initialize PeerId", err = error
    return

  trace "# Sending to: ", multiaddr = multiAddrs[0]

  var nextHopConn: Connection
  try:
    nextHopConn =
      await mixProto.switch.dial(firstMixPeerId, @[firstMixAddr], @[MixProtocolID])
    await nextHopConn.writeLp(sphinxPacket)
  except CatchableError as e:
    error "Failed to send message to next hop: ", err = e.msg
  finally:
    if nextHopConn != nil:
      try:
        await nextHopConn.close()
      except CatchableError as e:
        error "Failed to close outgoing stream: ", err = e.msg

proc createMixProtocol*(
    mixNodeInfo: MixNodeInfo,
    pubNodeInfo: Table[PeerId, MixPubInfo],
    switch: Switch,
    tagManager: TagManager,
    handler: ProtocolHandler,
): Result[MixProtocol, string] =
  let mixProto = new MixProtocol
  mixProto.mixNodeInfo = mixNodeInfo
  mixProto.pubNodeInfo = pubNodeInfo
  mixProto.switch = switch
  mixProto.tagManager = tagManager
  mixProto.pHandler = handler

  return ok(mixProto)

proc new*(
    T: typedesc[MixProtocol],
    index, numNodes: int,
    switch: Switch,
    nodeFolderInfoPath: string = ".",
): Result[T, string] =
  let mixNodeInfo = loadMixNodeInfo(index, nodeFolderInfoPath / fmt"nodeInfo").valueOr:
    return err("Failed to load mix node info for index " & $index & " - err: " & error)

  let pubNodeInfo = loadAllButIndexMixPubInfo(
    index, numNodes, nodeFolderInfoPath / fmt"pubInfo"
  ).valueOr:
    return err("Failed to load mix pub info for index " & $index & " - err: " & error)

  var sendHandlerFunc = proc(
      conn: Connection, proto: ProtocolType
  ): Future[void] {.async: (raises: [CancelledError]).} =
    try:
      await callHandler(switch, conn, proto)
    except CatchableError as e:
      error "Error during execution of MixProtocol handler: ", err = e.msg
    return

  let mixProto = T(
    mixNodeInfo: mixNodeInfo,
    pubNodeInfo: pubNodeInfo,
    switch: switch,
    tagManager: initTagManager(),
    pHandler: sendHandlerFunc,
  )

  mixProto.init()
  return ok(mixProto)

# Do we need to raise error here?
method init*(mixProtocol: MixProtocol) {.gcsafe, raises: [].} =
  proc handle(conn: Connection, proto: string) {.async: (raises: [CancelledError]).} =
    await mixProtocol.handleMixNodeConnection(conn)

  mixProtocol.lp_proto.codecs = @[MixProtocolID]
  mixProtocol.lp_proto.handler = handle
