import chronicles, chronos, sequtils, strutils, os, results
import std/[strformat, sysrand, tables], metrics
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
  rng: ref HmacDrbgContext
  # TODO: might require cleanup?
  idToSKey: Table[array[surbIdLen, byte], seq[(secret, key)]]
  fwdRBehavior: TableRef[string, fwdReadBehaviorCb]

proc hasFwdBehavior*(mixProto: MixProtocol, codec: string): bool =
  return mixProto.fwdRBehavior.hasKey(codec)

proc registerFwdReadBehavior*(
    mixProto: MixProtocol, codec: string, fwdBehavior: fwdReadBehaviorCb
) =
  mixProto.fwdRBehavior[codec] = fwdBehavior

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

  let processedSP = processSphinxPacket(sphinxPacket, mixPrivKey, mixProto.tagManager).valueOr:
    error "Failed to process Sphinx packet", err = error
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "INVALID_SPHINX"])
    return

  case processedSP.status
  of Exit:
    mix_messages_recvd.inc(labelValues = [$processedSP.status])
    # This is the exit node, forward to destination
    let msgChunk = MessageChunk.deserialize(processedSP.messageChunk).valueOr:
      error "Deserialization failed", err = error
      mix_messages_error.inc(labelValues = [$processedSP.status, "INVALID_SPHINX"])
      return

    let unpaddedMsg = unpadMessage(msgChunk).valueOr:
      error "Unpadding message failed", err = error
      mix_messages_error.inc(labelValues = [$processedSP.status, "INVALID_SPHINX"])
      return

    let deserialized = MixMessage.deserialize(unpaddedMsg).valueOr:
      error "Deserialization failed", err = error
      mix_messages_error.inc(labelValues = [$processedSP.status, "INVALID_SPHINX"])
      return

    let (surbs, message) = extractSURBs(deserialized.message).valueOr:
      error "Extracting surbs from payload failed", err = error
      mix_messages_error.inc(labelValues = [$processedSP.status, "INVALID_MSG_SURBS"])
      return

    trace "Exit node - Received mix message",
      receiver = multiAddr, message = deserialized.message, codec = deserialized.codec

    await mixProto.exitLayer.onMessage(
      deserialized.codec, message, processedSP.destination, surbs
    )

    mix_messages_forwarded.inc(labelValues = [$processedSP.status])
  of Reply:
    trace "# Reply", id = processedSP.id, delta_prime = processedSP.delta_prime
    # TODO: process reply at entry side
  of Intermediate:
    trace "# Intermediate: ", multiAddr = multiAddr
    # Add delay
    mix_messages_recvd.inc(labelValues = ["Intermediate"])
    await sleepAsync(milliseconds(processedSP.delayMs))

    # Forward to next hop
    let nextHopBytes = getHop(processedSP.nextHop)

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
      await nextHopConn.writeLp(processedSP.serializedSphinxPacket)
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

proc getMaxMessageSizeForCodec*(
    codec: string, numberOfSurbs: uint8 = 0
): Result[int, string] =
  let serializedMsg = ?MixMessage.init(@[], codec).serialize()
  var totalLen = serializedMsg.len + surbLenSize + (int(numberOfSurbs) * surbSize)
  if numberOfSurbs > 0:
    totalLen += surbIdLen
  if totalLen > dataSize:
    return err("cannot encode messages for this codec")
  return ok(dataSize - totalLen)

proc buildSurbs(
    mixProto: MixProtocol, numSurbs: uint8, skipPeer: PeerId
): Result[seq[SURB], string] =
  var response: seq[SURB]
  var surbSK: seq[(secret, key)] = @[]
  var id: I
  hmacDrbgGenerate(mixProto.rng[], id)

  for _ in uint8(0) ..< numSurbs:
    var
      multiAddrs: seq[string] = @[]
      publicKeys: seq[FieldElement] = @[]
      hops: seq[Hop] = @[]
      delay: seq[seq[byte]] = @[]

    # Select L mix nodes at random
    let numMixNodes = mixProto.pubNodeInfo.len

    if mixProto.pubNodeInfo.len < L:
      return err("No. of public mix nodes less than path length")

    var
      pubNodeInfoKeys = toSeq(mixProto.pubNodeInfo.keys)
      randPeerId: PeerId
      availableIndices = toSeq(0 ..< numMixNodes)

    var i = 0
    while i < L:
      let (multiAddr, mixPubKey, delayMillisec) =
        if i < L - 1:
          let randomIndexPosition = cryptoRandomInt(availableIndices.len).valueOr:
            return err("failed to generate random num: " & error)
          let selectedIndex = availableIndices[randomIndexPosition]
          randPeerId = pubNodeInfoKeys[selectedIndex]
          if randPeerId == skipPeer:
            continue

          availableIndices.del(randomIndexPosition)
          debug "Selected mix node for surbs: ", indexInPath = i, peerId = randPeerId
          let mixPubInfo = getMixPubInfo(mixProto.pubNodeInfo.getOrDefault(randPeerId))
          # Compute delay
          let delayMillisec = cryptoRandomInt(3).valueOr:
            mix_messages_error.inc(labelValues = ["Entry/SURB", "NON_RECOVERABLE"])
            return err("failed to generate random number: " & error)
          (mixPubInfo[0], mixPubInfo[1], delayMillisec)
        else:
          let mixPubInfo = mixProto.mixNodeInfo.getMixNodeInfo()
          (mixPubInfo[0], mixPubInfo[1], 0)

      multiAddrs.add(multiAddr)
      publicKeys.add(mixPubKey)

      let multiAddrBytes = multiAddrToBytes(multiAddr).valueOr:
        mix_messages_error.inc(labelValues = ["Entry/SURB", "INVALID_MIX_INFO"])
        return err("failed to convert multiaddress to bytes: " & error)

      hops.add(Hop.init(multiAddrBytes))

      delay.add(uint16ToBytes(delayMillisec.uint16))

      i = i + 1

    let surb = createSURB(publicKeys, delay, hops, id).valueOr:
      return err(error)

    surbSK.add((surb.secret.get(), surb.key))

    response.add(surb)

  if surbSK.len != 0:
    mixProto.idToSKey[id] = surbSK

  return ok(response)

proc prepareMsgWithSurbs(
    mixProto: MixProtocol, msg: seq[byte], numSurbs: uint8 = 0, skipPeer: PeerId
): Result[seq[byte], string] =
  let surbs = buildSurbs(mixProto, numSurbs, skipPeer).valueOr:
    return err(error)

  let serialized = ?serializeMessageWithSURBs(msg, surbs)

  ok(serialized)

proc sendPacket(
    mixProto: MixProtocol, multiAddrs: string, sphinxPacket: seq[byte], label: string
) {.async: (raises: []).} =
  # Send the wrapped message to the first mix node in the selected path
  let parts = multiAddrs.split("/p2p/")
  if parts.len != 2:
    error "Invalid multiaddress format", parts = parts
    mix_messages_error.inc(labelValues = [label, "NON_RECOVERABLE"])
    return

  let firstMixAddr = MultiAddress.init(parts[0]).valueOr:
    error "Failed to initialize MultiAddress", err = error
    mix_messages_error.inc(labelValues = [label, "NON_RECOVERABLE"])
    return

  let firstMixPeerId = PeerId.init(parts[1]).valueOr:
    error "Failed to initialize PeerId", err = error
    mix_messages_error.inc(labelValues = [label, "NON_RECOVERABLE"])
    return

  var nextHopConn: Connection
  try:
    nextHopConn =
      await mixProto.switch.dial(firstMixPeerId, @[firstMixAddr], @[MixProtocolID])
    await nextHopConn.writeLp(sphinxPacket)
    mix_messages_forwarded.inc(labelValues = ["Entry"])
  except CatchableError as e:
    error "Failed to send message to next hop: ", err = e.msg
    mix_messages_error.inc(labelValues = [label, "SEND_FAILED"])
  finally:
    if nextHopConn != nil:
      try:
        await nextHopConn.close()
      except CatchableError as e:
        error "Failed to close outgoing stream: ", err = e.msg

proc buildMessage(
    msg: seq[byte], codec: string, multiAddr: string
): Result[Message, (string, string)] =
  let mixMsg = MixMessage.init(msg, codec)

  let serialized = mixMsg.serialize().valueOr:
    return err(("message serialization failed: " & error, "NON_RECOVERABLE"))

  if len(serialized) > dataSize:
    return err(("message size exceeds maximum payload size", "INVALID_SIZE"))

  let peerId = getPeerIdFromMultiAddr(multiAddr).valueOr:
    return err(("failed to get peer id from multiaddress: " & error, "INVALID_DEST"))

  let paddedMsg = padMessage(serialized, peerId)

  let serializedMsgChunk = paddedMsg.serialize().valueOr:
    return err(("failed to serialize padded message: " & error, "NON_RECOVERABLE"))

  ok(Message.init(serializedMsgChunk))

type MixDestination* = object
  peerId*: PeerId
  address*: MultiAddress

proc init*(T: typedesc[MixDestination], peerId: PeerId, address: MultiAddress): T =
  T(peerId: peerId, address: address)

proc `$`*(d: MixDestination): string =
  $d.address & "/p2p/" & $d.peerId

proc anonymizeLocalProtocolSend*(
    mixProto: MixProtocol,
    msg: seq[byte],
    codec: string,
    destPeerId: Opt[PeerId],
    fwdDestination: Opt[MixDestination],
    numSurbs: uint8,
) {.async.} =
  ## destPeerId: use when dest == exit
  ## fwdDestination: use when dest != exit

  doAssert (destPeerId.isSome and fwdDestination.isNone) or
    (destPeerId.isNone and fwdDestination.isSome),
    "specify either the destPeerId or destination but not both"

  let (multiAddr, _, _, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)

  mix_messages_recvd.inc(labelValues = ["Entry"])

  var
    multiAddrs: seq[string] = @[]
    publicKeys: seq[FieldElement] = @[]
    hop: seq[Hop] = @[]
    delay: seq[seq[byte]] = @[]
    exitNode: PeerId

  # Select L mix nodes at random
  let numMixNodes = mixProto.pubNodeInfo.len
  var numAvailableNodes = numMixNodes

  info "Destination data", destPeerId, fwdDestination

  let skipDest = destPeerId.valueOr:
    fwdDestination.value.peerId
  if mixProto.pubNodeInfo.hasKey(skipDest):
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

  if destPeerId.isSome:
    let index = pubNodeInfoKeys.find(destPeerId.value())
    if index != -1:
      availableIndices.del(index)
    else:
      error "Destination does not support Mix"
      return

  var i = 0
  while i < L:
    if destPeerId.isSome and i == L - 1:
      randPeerId = destPeerId.value()
      exitNode = destPeerId.value()
    else:
      let randomIndexPosition = cryptoRandomInt(availableIndices.len).valueOr:
        error "Failed to genanrate random number", err = error
        mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
        return
      let selectedIndex = availableIndices[randomIndexPosition]
      randPeerId = pubNodeInfoKeys[selectedIndex]
      availableIndices.del(randomIndexPosition)

    if fwdDestination.isSome:
      # Skip the destination peer
      if randPeerId == fwdDestination.value().peerId:
        continue
      # Last hop will be the exit node that will forward the request
      if i == L - 1:
        exitNode = randPeerId

    debug "Selected mix node: ", indexInPath = i, peerId = randPeerId

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

  let destHop =
    if fwdDestination.isSome:
      #Encode destination
      let destAddrBytes = multiAddrToBytes($fwdDestination.value()).valueOr:
        error "Failed to convert multiaddress to bytes", err = error
        mix_messages_error.inc(labelValues = ["Entry", "INVALID_DEST"])
        return
      Hop.init(destAddrBytes)
    else:
      Hop()

  let msgWithSurbs = prepareMsgWithSurbs(mixProto, msg, numSurbs, exitNode).valueOr:
    error "Could not prepend SURBs", err = error
    return

  let message = buildMessage(msgWithSurbs, codec, multiAddr).valueOr:
    error "Error building message", err = error[0]
    mix_messages_error.inc(labelValues = ["Entry", error[1]])
    return

  # Wrap in Sphinx packet
  let sphinxPacket = wrapInSphinxPacket(message, publicKeys, delay, hop, destHop).valueOr:
    error "Failed to wrap in sphinx packet", err = error
    mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
    return

  # Send the wrapped message to the first mix node in the selected path
  await mixProto.sendPacket(multiAddrs[0], sphinxPacket, "Entry")

proc reply(
    mixProto: MixProtocol, surb: SURB, msg: seq[byte]
) {.async: (raises: [CancelledError]).} =
  let multiAddr = bytesToMultiAddr(surb.hop.getHop()).valueOr:
    error "could not obtain multiaddress from hop", err = error
    return

  # Message does not require a codec, as it is already associated to a specific I
  let message = buildMessage(msg, "", multiAddr).valueOr:
    error "could not build reply message", err = error
    return

  let sphinxPacket = useSURB(surb.header, surb.key, message).valueOr:
    error "Use SURB error", err = error
    return

  await mixProto.sendPacket(multiAddr, sphinxPacket, "Reply")

proc new*(
    T: typedesc[MixProtocol],
    mixNodeInfo: MixNodeInfo,
    pubNodeInfo: Table[PeerId, MixPubInfo],
    switch: Switch,
    tagManager: TagManager = TagManager.new(),
    rng: ref HmacDrbgContext = newRng(),
): T =
  let mixProto = new(T)
  mixProto.mixNodeInfo = mixNodeInfo
  mixProto.pubNodeInfo = pubNodeInfo
  mixProto.switch = switch
  mixProto.tagManager = tagManager
  mixProto.fwdRBehavior = newTable[string, fwdReadBehaviorCb]()

  let onReplyDialer = proc(
      surb: SURB, message: seq[byte]
  ) {.async: (raises: [CancelledError]).} =
    await mixProto.reply(surb, message)

  mixProto.exitLayer = ExitLayer.init(switch, onReplyDialer, mixProto.fwdRBehavior)
  mixProto.codecs = @[MixProtocolID]
  mixProto.rng = rng
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
    rng: ref HmacDrbgContext = newRng(),
): Result[T, string] =
  let mixNodeInfo = loadMixNodeInfo(index, nodeFolderInfoPath / fmt"nodeInfo").valueOr:
    return err("Failed to load mix node info for index " & $index & " - err: " & error)

  let pubNodeInfo = loadAllButIndexMixPubInfo(
    index, numNodes, nodeFolderInfoPath / fmt"pubInfo"
  ).valueOr:
    return err("Failed to load mix pub info for index " & $index & " - err: " & error)

  let mixProto =
    MixProtocol.new(mixNodeInfo, pubNodeInfo, switch, TagManager.new(), rng)

  return ok(mixProto)

# TODO: look into removing this
proc setNodePool*(
    mixProtocol: MixProtocol, mixNodeTable: Table[PeerId, MixPubInfo]
) {.gcsafe, raises: [].} =
  mixProtocol.pubNodeInfo = mixNodeTable

# TODO: look into removing this
proc getNodePoolSize*(mixProtocol: MixProtocol): int {.gcsafe, raises: [].} =
  mixProtocol.pubNodeInfo.len
