import chronicles, chronos, sequtils, strutils
import std/sysrand, serialization, metrics
import
  libp2p/
    [protocols/ping, protocols/protocol, stream/connection, stream/lpstream, switch]
import
  ./[
    config, curve25519, fragmentation, mix_message, mix_node, protocol, sphinx,
    tag_manager, utils, mix_metrics,
  ]

const MixProtocolID* = "/mix/1.0.0"

type MixProtocol* = ref object of LPProtocol
  mixNodeInfo: MixNodeInfo
  pubNodeInfo: Table[PeerId, MixPubInfo]
  switch: Switch
  tagManager: TagManager

proc loadMixNodeInfo*(index: int): Result[MixNodeInfo, string] =
  let readNode = readMixNodeInfoFromFile(index).valueOr:
    return err("Failed to load node info from file: " & error)
  ok(readNode)

proc loadAllButIndexMixPubInfo*(
    index, numNodes: int
): Result[Table[PeerId, MixPubInfo], string] =
  var pubInfoTable = initTable[PeerId, MixPubInfo]()
  for i in 0 ..< numNodes:
    if i != index:
      let pubInfo = readMixPubInfoFromFile(i).valueOr:
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

proc handleMixNodeConnection(mixProto: MixProtocol, conn: Connection) {.async.} =
  var receivedBytes = await conn.readLp(packetSize)

  if receivedBytes.len == 0:
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "NO_DATA"])
    return # No data, end of stream

  # Process the packet
  let (multiAddr, _, mixPrivKey, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)

  let processedPktRes =
    processSphinxPacket(receivedBytes, mixPrivKey, mixProto.tagManager)
  if processedPktRes.isErr:
    error "Failed to process Sphinx packet", err = processedPktRes.error
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "INVALID_SPHINX"])
    return
  let (nextHop, delay, processedPkt, status) = processedPktRes.get()

  case status
  of Exit:
    mix_messages_recvd.inc(labelValues = ["Exit"])
    # This is the exit node, forward to destination
    let msgChunk = deserializeMessageChunk(processedPkt).valueOr:
      error "Deserialization failed", err = error
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_SPHINX"])
      return

    let unpaddedMsg = unpadMessage(msgChunk).valueOr:
      error "Unpadding message failed", err = error
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_SPHINX"])
      return

    let deserializedResult = deserializeMixMessage(unpaddedMsg).valueOr:
      error "Deserialization failed", err = error
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_SPHINX"])
      return

    let (message, protocol) = getMixMessage(deserializedResult)
    info "####################################### Exit node - Received mix message: ",
      receiver = multiAddr, message = message

    # Add delay
    let delayMillis = (delay[0].int shl 8) or delay[1].int
    await sleepAsync(milliseconds(delayMillis))

    # Forward to destination
    let destBytes = getHop(nextHop)

    let fullAddrStr = bytesToMultiAddr(destBytes).valueOr:
      error "Failed to convert bytes to multiaddress", err = error
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_DEST"])
      return

    let parts = fullAddrStr.split("/p2p/")
    if parts.len != 2:
      error "Invalid multiaddress format", parts = parts
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_DEST"])
      return

    let
      locationAddrStr = parts[0]
      peerIdStr = parts[1]

    # Create MultiAddress and PeerId
    let locationAddr = MultiAddress.init(locationAddrStr).valueOr:
      error "Failed to parse location multiaddress: ", err = error
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_DEST"])
      return

    let peerId = PeerId.init(peerIdStr).valueOr:
      error "Failed to initialize PeerId", err = error
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_DEST"])
      return

    var destConn: Connection
    try:
      destConn = await mixProto.switch.dial(peerId, @[locationAddr], $protocol)
      await destConn.writeLp(message)
    except CatchableError as e:
      error "Failed to dial next hop: ", err = e.msg
      mix_messages_error.inc(labelValues = ["Exit", "DAIL_FAILED"])
    mix_messages_forwarded.inc(labelValues = ["Exit"])
  of Success:
    # Add delay
    let delayMillis = (delay[0].int shl 8) or delay[1].int
    info "################################################################# Intermediate node for mixMsg, adding delay: ",
      delay = delayMillis
    mix_messages_recvd.inc(labelValues = ["Intermediate"])
    await sleepAsync(milliseconds(delayMillis))
    # Forward to next hop
    let nextHopBytes = getHop(nextHop)

    let fullAddrStr = bytesToMultiAddr(nextHopBytes).valueOr:
      error "Failed to convert bytes to multiaddress", err = error
      mix_messages_error.inc(labelValues = ["Intermediate", "INVALID_NEXTHOP"])
      return

    let parts = fullAddrStr.split("/p2p/")
    if parts.len != 2:
      error "Invalid multiaddress format", parts = parts
      mix_messages_error.inc(labelValues = ["Intermediate", "INVALID_NEXTHOP"])
      return

    let
      locationAddrStr = parts[0]
      peerIdStr = parts[1]
    info "################################################################# Intermediate node, forwarding to next Hop ",
      nextHop = peerIdStr

    # Create MultiAddress and PeerId
    let locationAddr = MultiAddress.init(locationAddrStr).valueOr:
      error "Failed to parse location multiaddress: ", err = error
      mix_messages_error.inc(labelValues = ["Intermediate", "INVALID_NEXTHOP"])
      return

    let peerId = PeerId.init(peerIdStr).valueOr:
      error "Failed to initialize PeerId", err = error
      mix_messages_error.inc(labelValues = ["Intermediate", "INVALID_NEXTHOP"])
      return

    var nextHopConn: Connection
    try:
      nextHopConn = await mixProto.switch.dial(peerId, @[locationAddr], MixProtocolID)
      await nextHopConn.writeLp(processedPkt)
      await nextHopConn.close()
    except CatchableError as e:
      error "Failed to dial next hop: ", err = e.msg
      mix_messages_error.inc(labelValues = ["Intermediate", "DAIL_FAILED"])
    mix_messages_forwarded.inc(labelValues = ["Intermediate"])
  of Duplicate:
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "DUPLICATE"])
    discard
  of InvalidMAC:
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "INVALID_MAC"])
    discard

proc anonymizeLocalProtocolSend*(
    mixProto: MixProtocol,
    msg: seq[byte],
    proto: ProtocolType,
    destMultiAddr: MultiAddress,
    destPeerId: PeerId,
) {.async.} =
  let mixMsg = initMixMessage(msg, proto)

  let serialized = serializeMixMessage(mixMsg).valueOr:
    error "Serialization failed", err = error
    mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
    return
  if len(serialized) > dataSize:
    error "Message size exceeds maximum payload size",
      size = len(serialized), limit = dataSize
    mix_messages_error.inc(labelValues = ["Entry", "INVALID_SIZE"])
    return
  let (multiAddr, _, _, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)

  let peerId = getPeerIdFromMultiAddr(multiAddr).valueOr:
    error "Failed to get peer id from multiaddress", err = error
    mix_messages_error.inc(labelValues = ["Entry", "INVALID_DEST"])
    return
  mix_messages_recvd.inc(labelValues = ["Entry"])

  let paddedMsg = padMessage(serialized, peerID)

  var
    multiAddrs: seq[string] = @[]
    publicKeys: seq[FieldElement] = @[]
    hop: seq[Hop] = @[]
    delay: seq[seq[byte]] = @[]

  # Select L mix nodes at random
  let numMixNodes = mixProto.pubNodeInfo.len
  var numAvailableNodes = numMixNodes
  if mixProto.pubNodeInfo.hasKey(destPeerId):
    info "Destination peer is a mix node", destPeerId = destPeerId
    numAvailableNodes = numMixNodes - 1

  if numAvailableNodes < L:
    error "No. of public mix nodes less than path length.",
      numMixNodes = numAvailableNodes, pathLength = L
    mix_messages_error.inc(labelValues = ["Entry", "LOW_MIX_POOL"])
    return

  var
    pubNodeInfoKeys = toSeq(mixProto.pubNodeInfo.keys)
    randPeerId: PeerId
    availableIndices = toSeq(0 ..< numMixNodes)
    i = 0
  while i < L:
    let randomIndexPosition = cryptoRandomInt(availableIndices.len).valueOr:
      error "Failed to generate random number", err = error
      mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
      return
    let selectedIndex = availableIndices[randomIndexPosition]
    randPeerId = pubNodeInfoKeys[selectedIndex]
    availableIndices.del(randomIndexPosition)
    # Skip the destination peer
    if randPeerId == destPeerId:
      continue

    info "Selected mix node: ", indexInPath = i, peerId = randPeerId

    # Extract multiaddress, mix public key, and hop
    let (multiAddr, mixPubKey, _) =
      getMixPubInfo(mixProto.pubNodeInfo.getOrDefault(randPeerId))
    multiAddrs.add(multiAddr)
    publicKeys.add(mixPubKey)

    let multiAddrBytes = multiAddrToBytes(multiAddr).valueOr:
      error "Failed to convert multiaddress to bytes", err = error
      mix_messages_error.inc(labelValues = ["Entry", "INVALID_MIX_INFO"])
      #TODO: should we skip and pick a different node here??
      return

    hop.add(initHop(multiAddrBytes))

    # Compute delay
    let delayMilliSec = cryptoRandomInt(3).valueOr:
      error "Failed to generate random number", err = error
      mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
      return
    delay.add(uint16ToBytes(uint16(delayMilliSec)))
    i = i + 1
  let serializedRes = serializeMessageChunk(paddedMsg).valueOr:
    error "Failed to serialize padded message", err = error
    mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
    return

  #Encode destination
  let dest = $destMultiAddr & "/p2p/" & $destPeerId
  let destAddrBytes = multiAddrToBytes(dest).valueOr:
    error "Failed to convert multiaddress to bytes", err = error
    mix_messages_error.inc(labelValues = ["Entry", "INVALID_DEST"])
    return
  let destHop = initHop(destAddrBytes)

  # Wrap in Sphinx packet
  let sphinxPacket = wrapInSphinxPacket(
    initMessage(serializedRes), publicKeys, delay, hop, destHop
  ).valueOr:
    error "Failed to wrap in sphinx packet", err = error
    mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
    return

  # Send the wrapped message to the first mix node in the selected path
  let parts = multiAddrs[0].split("/p2p/")
  if parts.len != 2:
    error "Invalid multiaddress format", parts = parts
    mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
    return

  let firstMixAddr = MultiAddress.init(parts[0]).valueOr:
    error "Failed to initialize MultiAddress", err = error
    mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
    return

  let firstMixPeerId = PeerId.init(parts[1]).valueOr:
    error "Failed to initialize PeerId", err = error
    mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
    return

  var nextHopConn: Connection
  try:
    nextHopConn =
      await mixProto.switch.dial(firstMixPeerId, @[firstMixAddr], @[MixProtocolID])
    await nextHopConn.writeLp(sphinxPacket)
    await nextHopConn.close()
  except CatchableError as e:
    error "Failed to send message to next hop: ", err = e.msg
    mix_messages_error.inc(labelValues = ["Entry", "SEND_FAILED"])
  mix_messages_forwarded.inc(labelValues = ["Entry"])
  info "#################################################### Sent: ",
    sender = multiAddr, message = msg

proc new*(
    T: typedesc[MixProtocol], index, numNodes: int, switch: Switch
): Result[T, string] =
  let mixNodeInfo = loadMixNodeInfo(index).valueOr:
    return err("Failed to load mix node info for index " & $index)

  let pubNodeInfo = loadAllButIndexMixPubInfo(index, numNodes).valueOr:
    return err("Failed to load mix pub info for index " & $index)

  let mixProto = T(
    mixNodeInfo: mixNodeInfo,
    pubNodeInfo: pubNodeInfo,
    switch: switch,
    tagManager: initTagManager(),
  )
  mixProto.init()
  return ok(mixProto)

proc init*(
    mixProtocol: MixProtocol,
    localMixNodeInfo: MixNodeInfo,
    switch: Switch,
    mixNodeTable: Table[PeerId, MixPubInfo],
) =
  #if mixNodeTable.len == 0:
  # TODO:This is temporary check for testing, needs to be removed later
  # probably protocol can be initiated without any mix nodes itself,
  # and can be later supplied with nodes as they are discovered.
  #return err("No mix nodes passed for the protocol initialization.")

  mixProtocol.mixNodeInfo = localMixNodeInfo
  mixProtocol.switch = switch
  mixProtocol.pubNodeInfo = mixNodeTable
  mixProtocol.tagManager = initTagManager()

  mixProtocol.init()

method init*(mixProtocol: MixProtocol) {.gcsafe, raises: [].} =
  proc handle(conn: Connection, proto: string) {.async.} =
    await mixProtocol.handleMixNodeConnection(conn)

  mixProtocol.codecs = @[MixProtocolID]
  mixProtocol.handler = handle

method setNodePool*(
    mixProtocol: MixProtocol, mixNodeTable: Table[PeerId, MixPubInfo]
) {.gcsafe, raises: [].} =
  mixProtocol.pubNodeInfo = mixNodeTable

method getNodePoolSize*(mixProtocol: MixProtocol): int {.gcsafe, raises: [].} =
  mixProtocol.pubNodeInfo.len
