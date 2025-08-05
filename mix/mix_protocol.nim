import chronicles, chronos, sequtils, strutils, os, results
import std/[strformat, sysrand], metrics
import
  ./[
    config, curve25519, exit_connection, fragmentation, mix_message, mix_node, sphinx,
    serialization, tag_manager, utils, mix_metrics, exit_layer,
  ]
import libp2p
import
  libp2p/
    [protocols/ping, protocols/protocol, stream/connection, stream/lpstream, switch]

const MixProtocolID* = "/mix/1.0.0"

type MixProtocol* = ref object of LPProtocol
  mixNodeInfo: MixNodeInfo
  pubNodeInfo: Table[PeerId, MixPubInfo]
  switch: Switch
  tagManager: TagManager
  exitLayer: ExitLayer

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
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "NO_DATA"])
    return # No data, end of stream

  # Process the packet
  let (multiAddr, _, mixPrivKey, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)

  let sphinxPacket = SphinxPacket.deserialize(receivedBytes).valueOr:
    error "Sphinx packet deserialization error", err = error
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "INVALID_SPHINX"])
    return

  let (nextHop, delay, processedPkt, status) = processSphinxPacket(
    sphinxPacket, mixPrivKey, mixProto.tagManager
  ).valueOr:
    error "Failed to process Sphinx packet", err = error
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "INVALID_SPHINX"])
    return

  case status
  of Exit:
    mix_messages_recvd.inc(labelValues = ["Exit"])
    # This is the exit node, forward to destination
    let msgChunk = MessageChunk.deserialize(processedPkt).valueOr:
      error "Deserialization failed", err = error
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_SPHINX"])
      return

    let unpaddedMsg = unpadMessage(msgChunk).valueOr:
      error "Unpadding message failed", err = error
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_SPHINX"])
      return

    let deserialized = MixMessage.deserialize(unpaddedMsg).valueOr:
      error "Deserialization failed", err = error
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_SPHINX"])
      return

    trace "Exit node - Received mix message: ",
      receiver = multiAddr, message = deserialized.message, codec = deserialized.codec

    await mixProto.exitLayer.onMessage(
      deserialized.codec, deserialized.message, nextHop
    )

    mix_messages_forwarded.inc(labelValues = ["Exit"])
  of Intermediate:
    trace "# Intermediate: ", multiAddr = multiAddr
    # Add delay
    let delayMillis = (delay[0].int shl 8) or delay[1].int
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
      mix_messages_forwarded.inc(labelValues = ["Intermediate"])
    except CatchableError as e:
      error "Failed to dial next hop: ", err = e.msg
    finally:
      if nextHopConn != nil:
        try:
          await nextHopConn.close()
        except CatchableError as e:
          error "Failed to close outgoing stream: ", err = e.msg
      mix_messages_error.inc(labelValues = ["Intermediate", "DAIL_FAILED"])
  of Duplicate:
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "DUPLICATE"])
    discard
  of InvalidMAC:
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "INVALID_MAC"])
    discard

proc getMaxMessageSizeForCodec*(codec: string): Result[int, string] =
  let serializedMsg = ?MixMessage.init(@[], codec).serialize()
  if serializedMsg.len > dataSize:
    return err("cannot encode messages for this codec")
  return ok(dataSize - serializedMsg.len)

proc anonymizeLocalProtocolSend*(
    mixProto: MixProtocol,
    msg: seq[byte],
    codec: string,
    destPeerId: PeerId,
    destForwardToAddr: Opt[MultiAddress],
) {.async.} =
  let mixMsg = MixMessage.init(msg, codec)

  let serialized = mixMsg.serialize().valueOr:
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

  let paddedMsg = padMessage(serialized, peerId)

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

  if destForwardToAddr.isNone:
    let index = pubNodeInfoKeys.find(destPeerId)
    if index != -1:
      availableIndices.del(index)
    else:
      error "Destination does not support Mix"
      return

  var i = 0
  while i < L:
    if destForwardToAddr.isNone and i == L - 1:
      randPeerId = destPeerId
    else:
      let randomIndexPosition = cryptoRandomInt(availableIndices.len).valueOr:
        error "Failed to genanrate random number", err = error
        mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
        return
      let selectedIndex = availableIndices[randomIndexPosition]
      randPeerId = pubNodeInfoKeys[selectedIndex]
      availableIndices.del(randomIndexPosition)

    # Skip the destination peer
    if destForwardToAddr.isSome and randPeerId == destPeerId:
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

    hop.add(Hop.init(multiAddrBytes))

    # Compute delay
    let delayMillisec =
      if i != L - 1:
        cryptoRandomInt(3).valueOr:
          error "Failed to generate random number", err = error
          mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
          return
      else:
        0 # Last hop does not require a delay

    delay.add(uint16ToBytes(delayMillisec.uint16))

    i = i + 1
  let serializedMsgChunk = paddedMsg.serialize().valueOr:
    error "Failed to serialize padded message", err = error
    mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
    return

  let destHop =
    if destForwardToAddr.isSome:
      #Encode destination
      let dest = $destForwardToAddr.value & "/p2p/" & $destPeerId
      let destAddrBytes = multiAddrToBytes(dest).valueOr:
        error "Failed to convert multiaddress to bytes", err = error
        mix_messages_error.inc(labelValues = ["Entry", "INVALID_DEST"])
        return
      Hop.init(destAddrBytes)
    else:
      Hop()

  # Wrap in Sphinx packet
  let sphinxPacket = wrapInSphinxPacket(
    Message.init(serializedMsgChunk), publicKeys, delay, hop, destHop
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
    mix_messages_forwarded.inc(labelValues = ["Entry"])
  except CatchableError as e:
    error "Failed to send message to next hop: ", err = e.msg
    mix_messages_error.inc(labelValues = ["Entry", "SEND_FAILED"])
  finally:
    if nextHopConn != nil:
      try:
        await nextHopConn.close()
      except CatchableError as e:
        error "Failed to close outgoing stream: ", err = e.msg

proc new*(
    T: typedesc[MixProtocol],
    mixNodeInfo: MixNodeInfo,
    pubNodeInfo: Table[PeerId, MixPubInfo],
    switch: Switch,
    tagManager: TagManager,
): T =
  let mixProto = new(T)
  mixProto.mixNodeInfo = mixNodeInfo
  mixProto.pubNodeInfo = pubNodeInfo
  mixProto.switch = switch
  mixProto.tagManager = tagManager
  mixProto.exitLayer = ExitLayer.init(switch)
  mixProto.codecs = @[MixProtocolID]
  mixProto.handler = proc(
      conn: Connection, proto: string
  ) {.async: (raises: [CancelledError]).} =
    await mixProto.handleMixNodeConnection(conn)

  mixProto

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

  let mixProto = MixProtocol.new(mixNodeInfo, pubNodeInfo, switch, TagManager.new())

  return ok(mixProto)

# TODO: look into removing this
proc setNodePool*(
    mixProtocol: MixProtocol, mixNodeTable: Table[PeerId, MixPubInfo]
) {.gcsafe, raises: [].} =
  mixProtocol.pubNodeInfo = mixNodeTable

# TODO: look into removing this
proc getNodePoolSize*(mixProtocol: MixProtocol): int {.gcsafe, raises: [].} =
  mixProtocol.pubNodeInfo.len
