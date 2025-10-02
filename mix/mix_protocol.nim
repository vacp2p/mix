import chronicles, chronos, sequtils, strutils, os, results
import std/[strformat, sysrand, tables], metrics, times
import
  ./[
    config, curve25519, exit_connection, fragmentation, mix_message, mix_node, sphinx,
    serialization, tag_manager, utils, mix_metrics, exit_layer,
  ]
import libp2p
import
  libp2p/
    [protocols/ping, protocols/protocol, stream/connection, stream/lpstream, switch]

when defined(enable_mix_benchmarks):
  import stew/endians2

const MixProtocolID* = "/mix/1.0.0"

type
  IGroup = ref object
    members: HashSet[I]

  ConnCreds = object
    igroup: IGroup
    incoming: AsyncQueue[seq[byte]]
    surbSecret: secret
    surbKey: key

## Mix Protocol defines a decentralized anonymous message routing layer for libp2p networks.
## It enables sender anonymity by routing each message through a decentralized mix overlay 
## network composed of participating libp2p nodes, known as mix nodes. Each message is 
## routed independently in a stateless manner, allowing other libp2p protocols to selectively 
## anonymize messages without modifying their core protocol behavior.
type MixProtocol* = ref object of LPProtocol
  mixNodeInfo: MixNodeInfo
  pubNodeInfo: Table[PeerId, MixPubInfo]
  switch: Switch
  tagManager: TagManager
  exitLayer: ExitLayer
  rng: ref HmacDrbgContext
  # TODO: verify if this requires cleanup for cases in which response never arrives (and connection is closed)
  connCreds: Table[I, ConnCreds]
  destReadBehavior: TableRef[string, destReadBehaviorCb]

proc benchmarkLog*(
    eventName: static[string],
    myPeerId: PeerId,
    startTime: Time,
    msgId: uint64,
    orig: uint64,
    fromPeerId: Opt[PeerId],
    toPeerId: Opt[PeerId],
) =
  let endTime = getTime()
  let procDelay = (endTime - startTime).inMilliseconds()
  let fromPeerId =
    if fromPeerId.isNone:
      "None"
    else:
      fromPeerId.get().shortLog()
  let toPeerId =
    if toPeerId.isNone:
      "None"
    else:
      toPeerId.get().shortLog()
  info eventName,
    msgId, fromPeerId, toPeerId, myPeerId, orig, current = startTime, procDelay

proc hasDestReadBehavior*(mixProto: MixProtocol, codec: string): bool =
  return mixProto.destReadBehavior.hasKey(codec)

proc registerDestReadBehavior*(
    mixProto: MixProtocol, codec: string, fwdBehavior: destReadBehaviorCb
) =
  mixProto.destReadBehavior[codec] = fwdBehavior

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

  when defined(enable_mix_benchmarks):
    var metadata: seq[byte]
    var fromPeerId: PeerId

  try:
    when defined(enable_mix_benchmarks):
      metadata = await conn.readLp(16)
      fromPeerId = conn.peerId

    receivedBytes = await conn.readLp(packetSize)
  except Exception as e:
    error "Failed to read: ", err = e.msg
  finally:
    if conn != nil:
      try:
        await conn.close()
      except CatchableError as e:
        error "Failed to close incoming stream: ", err = e.msg

  when defined(enable_mix_benchmarks):
    let startTime = getTime()

    if metadata.len == 0:
      mix_messages_error.inc(labelValues = ["Intermediate/Exit", "NO_DATA"])
      return # No data, end of stream  

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

  when defined(enable_mix_benchmarks):
    let
      orig = uint64.fromBytesLE(metadata[0 ..< 8])
      msgId = uint64.fromBytesLE(metadata[8 ..< 16])

  case processedSP.status
  of Exit:
    mix_messages_recvd.inc(labelValues = [$processedSP.status])
    # This is the exit node, forward to destination
    let msgChunk = MessageChunk.deserialize(processedSP.messageChunk).valueOr:
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

    let (surbs, message) = extractSURBs(deserialized.message).valueOr:
      error "Extracting surbs from payload failed", err = error
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_MSG_SURBS"])
      return

    trace "Exit node - Received mix message",
      receiver = multiAddr, message = deserialized.message, codec = deserialized.codec

    when defined(enable_mix_benchmarks):
      benchmarkLog "Exit",
        mixProto.switch.peerInfo.peerId,
        startTime,
        msgId,
        orig,
        Opt.some(fromPeerId),
        Opt.none(PeerId)

    await mixProto.exitLayer.onMessage(
      deserialized.codec, message, processedSP.destination, surbs
    )

    mix_messages_forwarded.inc(labelValues = ["Exit"])
  of Reply:
    trace "# Reply", id = processedSP.id
    try:
      if not mixProto.connCreds.hasKey(processedSP.id):
        mix_messages_error.inc(labelValues = ["Sender/Reply", "NO_CONN_FOUND"])
        return

      let connCred = mixProto.connCreds[processedSP.id]

      let reply = processReply(
        connCred.surbKey, connCred.surbSecret, processedSP.delta_prime
      ).valueOr:
        error "could not process reply", id = processedSP.id
        mix_messages_error.inc(labelValues = ["Reply", "INVALID_CREDS"])
        return

      # Deleting all other SURBs associated to this
      for id in connCred.igroup.members:
        mixProto.connCreds.del(id)

      let msgChunk = MessageChunk.deserialize(reply).valueOr:
        error "Deserialization failed", err = error
        mix_messages_error.inc(labelValues = ["Reply", "INVALID_SPHINX"])
        return

      let unpaddedMsg = unpadMessage(msgChunk).valueOr:
        error "Unpadding message failed", err = error
        mix_messages_error.inc(labelValues = ["Reply", "INVALID_SPHINX"])
        return

      let deserialized = MixMessage.deserialize(unpaddedMsg).valueOr:
        error "Deserialization failed", err = error
        mix_messages_error.inc(labelValues = ["Reply", "INVALID_SPHINX"])
        return

      when defined(enable_mix_benchmarks):
        benchmarkLog "Reply",
          mixProto.switch.peerInfo.peerId,
          startTime,
          msgId,
          orig,
          Opt.some(fromPeerId),
          Opt.none(PeerId)

      await connCred.incoming.put(deserialized.message)
    except KeyError:
      doAssert false, "checked with hasKey"
  of Intermediate:
    trace "# Intermediate: ", multiAddr = multiAddr
    # Add delay
    mix_messages_recvd.inc(labelValues = ["Intermediate"])
    await sleepAsync(chronos.milliseconds(processedSP.delayMs))

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

    when defined(enable_mix_benchmarks):
      benchmarkLog "Intermediate",
        mixProto.switch.peerInfo.peerId,
        startTime,
        msgId,
        orig,
        Opt.some(fromPeerId),
        Opt.some(peerId)

    var nextHopConn: Connection
    try:
      nextHopConn = await mixProto.switch.dial(peerId, @[locationAddr], MixProtocolID)

      when defined(enable_mix_benchmarks):
        await nextHopConn.writeLp(metadata)

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
      mix_messages_error.inc(labelValues = ["Intermediate", "DIAL_FAILED"])
  of Duplicate:
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "DUPLICATE"])
    discard
  of InvalidMAC:
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "INVALID_MAC"])
    discard

proc getMaxMessageSizeForCodec*(
    codec: string, numberOfSurbs: uint8 = 0
): Result[int, string] =
  ## Computes the maximum payload size (in bytes) available for a message when encoded  
  ## with the given `codec`, optionally including space for the chosen number of surbs.  
  ## Returns an error if the codec + surb overhead exceeds the data capacity.  
  let serializedMsg = ?MixMessage.init(@[], codec).serialize()
  var totalLen = serializedMsg.len + surbLenSize + (int(numberOfSurbs) * surbSize)
  if numberOfSurbs > 0:
    totalLen += surbIdLen
  if totalLen > dataSize:
    return err("cannot encode messages for this codec")
  return ok(dataSize - totalLen)

proc buildSurbs(
    mixProto: MixProtocol,
    incoming: AsyncQueue[seq[byte]],
    numSurbs: uint8,
    destPeerId: PeerId,
    exitPeerId: PeerId,
): Result[seq[SURB], string] =
  var response: seq[SURB]
  var igroup = IGroup(members: initHashSet[I]())

  for _ in uint8(0) ..< numSurbs:
    var
      id: I
      multiAddrs: seq[string] = @[]
      publicKeys: seq[FieldElement] = @[]
      hops: seq[Hop] = @[]
      delay: seq[seq[byte]] = @[]

    hmacDrbgGenerate(mixProto.rng[], id)

    # Select L mix nodes at random

    if mixProto.pubNodeInfo.len < L:
      return err("No. of public mix nodes less than path length")

    # Remove exit and dest node from nodes to consider for surbs
    var pubNodeInfoKeys =
      mixProto.pubNodeInfo.keys.toSeq().filterIt(it != exitPeerId and it != destPeerId)
    var availableIndices = toSeq(0 ..< pubNodeInfoKeys.len)

    # Select L mix nodes at random
    var i = 0
    while i < L:
      let (multiAddr, mixPubKey, delayMillisec) =
        if i < L - 1:
          let randomIndexPosition = cryptoRandomInt(availableIndices.len).valueOr:
            return err("failed to generate random num: " & error)
          let selectedIndex = availableIndices[randomIndexPosition]
          let randPeerId = pubNodeInfoKeys[selectedIndex]
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

    igroup.members.incl(id)
    mixProto.connCreds[id] = ConnCreds(
      igroup: igroup,
      surbSecret: surb.secret.get(),
      surbKey: surb.key,
      incoming: incoming,
    )
    response.add(surb)

  return ok(response)

proc prepareMsgWithSurbs(
    mixProto: MixProtocol,
    incoming: AsyncQueue[seq[byte]],
    msg: seq[byte],
    numSurbs: uint8 = 0,
    destPeerId: PeerId,
    exitPeerId: PeerId,
): Result[seq[byte], string] =
  let surbs = mixProto.buildSurbs(incoming, numSurbs, destPeerId, exitPeerId).valueOr:
    return err(error)

  let serialized = ?serializeMessageWithSURBs(msg, surbs)

  ok(serialized)

type SendPacketType* = enum
  Entry
  Reply

type SendPacketConfig = object
  logType: SendPacketType
  when defined(enable_mix_benchmarks):
    startTime: Time
    orig: uint64
    msgId: uint64
    origAndMsgId: seq[byte]

proc sendPacket(
    mixProto: MixProtocol,
    multiAddrs: string,
    sphinxPacket: seq[byte],
    config: SendPacketConfig,
) {.async: (raises: []).} =
  let label = $config.logType
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

  when defined(enable_mix_benchmarks):
    if config.logType == Entry:
      benchmarkLog "Sender",
        mixProto.switch.peerInfo.peerId,
        config.startTime,
        config.msgId,
        config.orig,
        Opt.none(PeerId),
        Opt.some(firstMixPeerId)

  var nextHopConn: Connection
  try:
    nextHopConn =
      await mixProto.switch.dial(firstMixPeerId, @[firstMixAddr], @[MixProtocolID])

    when defined(enable_mix_benchmarks):
      await nextHopConn.writeLp(config.origAndMsgId)

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

## Represents the final target of a mixnet message.  
## contains the peer id and multiaddress of the destination node.
type DestinationType* = enum
  ForwardAddr
  MixNode

type MixDestination* = object
  peerId: PeerId
  case kind: DestinationType
  of ForwardAddr:
    address: MultiAddress
  else:
    discard

proc `$`*(d: MixDestination): string =
  case d.kind
  of ForwardAddr:
    return "MixDestination[ForwardAddr](" & $d.address & "/p2p/" & $d.peerId & ")"
  of MixNode:
    return "MixDestination[MixNode](" & $d.peerId & ")"

when defined(mix_experimental_exit_is_destination):
  proc exitNode*(T: typedesc[MixDestination], p: PeerId): T =
    T(kind: DestinationType.MixNode, peerId: p)

proc forwardToAddr*(T: typedesc[MixDestination], p: PeerId, address: MultiAddress): T =
  T(kind: DestinationType.ForwardAddr, peerId: p, address: address)

proc init*(T: typedesc[MixDestination], p: PeerId, address: MultiAddress): T =
  MixDestination.forwardToAddr(p, address)

proc anonymizeLocalProtocolSend*(
    mixProto: MixProtocol,
    incoming: AsyncQueue[seq[byte]],
    msg: seq[byte],
    codec: string,
    destination: MixDestination,
    numSurbs: uint8,
) {.async.} =
  when not defined(mix_experimental_exit_is_destination):
    doAssert destination.kind == ForwardAddr, "Only exit != destination is allowed"

  var config = SendPacketConfig(logType: Entry)
  when defined(enable_mix_benchmarks):
    config.startTime = getTime()

  let (multiAddr, _, _, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)

  when defined(enable_mix_benchmarks):
    # Assumes a fixed gossipsub message layout of 100
    config.orig = uint64.fromBytesLE(msg[5 ..< 13])
    config.msgId = uint64.fromBytesLE(msg[13 ..< 21])
    config.origAndMsgId = msg[5 ..< 21]

  mix_messages_recvd.inc(labelValues = ["Entry"])

  var
    multiAddrs: seq[string] = @[]
    publicKeys: seq[FieldElement] = @[]
    hop: seq[Hop] = @[]
    delay: seq[seq[byte]] = @[]
    exitPeerId: PeerId

  # Select L mix nodes at random
  let numMixNodes = mixProto.pubNodeInfo.len
  var numAvailableNodes = numMixNodes

  debug "Destination data", destination

  if mixProto.pubNodeInfo.hasKey(destination.peerId):
    numAvailableNodes = numMixNodes - 1

  if numAvailableNodes < L:
    error "No. of public mix nodes less than path length.",
      numMixNodes = numAvailableNodes, pathLength = L
    mix_messages_error.inc(labelValues = ["Entry", "LOW_MIX_POOL"])
    return

  # Skip the destination peer
  var pubNodeInfoKeys = mixProto.pubNodeInfo.keys.toSeq()
  var availableIndices = toSeq(0 ..< pubNodeInfoKeys.len)

  let index = pubNodeInfoKeys.find(destination.peerId)
  if index != -1:
    availableIndices.del(index)
  else:
    if destination.kind == MixNode:
      error" Destination does not support mix"
      return

  var i = 0
  while i < L:
    let randomIndexPosition = cryptoRandomInt(availableIndices.len).valueOr:
      error "Failed to generate random number", err = error
      mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
      return
    let selectedIndex = availableIndices[randomIndexPosition]
    var randPeerId = pubNodeInfoKeys[selectedIndex]
    availableIndices.del(randomIndexPosition)

    if destination.kind == ForwardAddr and randPeerId == destination.peerId:
      # Skip the destination peer
      continue

    if i == L - 1:
      case destination.kind
      of ForwardAddr:
        # Last hop will be the exit node that will forward the request
        exitPeerId = randPeerId
      of MixNode:
        # Exit node will be the destination
        exitPeerId = destination.peerId
        randPeerId = destination.peerId

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

  #Encode destination
  let destHop =
    if destination.kind == ForwardAddr:
      let destAddrBytes = multiAddrToBytes(
        $destination.address & "/p2p/" & $destination.peerId
      ).valueOr:
        error "Failed to convert multiaddress to bytes", err = error
        mix_messages_error.inc(labelValues = ["Entry", "INVALID_DEST"])
        return
      Hop.init(destAddrBytes)
    else:
      Hop()

  let msgWithSurbs = mixProto.prepareMsgWithSurbs(
    incoming, msg, numSurbs, destination.peerId, exitPeerId
  ).valueOr:
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
  await mixProto.sendPacket(multiAddrs[0], sphinxPacket, config)

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

  await mixProto.sendPacket(multiAddr, sphinxPacket, SendPacketConfig(logType: Reply))

proc init*(
    mixProto: MixProtocol,
    mixNodeInfo: MixNodeInfo,
    pubNodeInfo: Table[PeerId, MixPubInfo],
    switch: Switch,
    tagManager: TagManager = TagManager.new(),
    rng: ref HmacDrbgContext = newRng(),
) =
  mixProto.mixNodeInfo = mixNodeInfo
  mixProto.pubNodeInfo = pubNodeInfo
  mixProto.switch = switch
  mixProto.tagManager = tagManager
  mixProto.destReadBehavior = newTable[string, destReadBehaviorCb]()

  let onReplyDialer = proc(
      surb: SURB, message: seq[byte]
  ) {.async: (raises: [CancelledError]).} =
    await mixProto.reply(surb, message)

  mixProto.exitLayer = ExitLayer.init(switch, onReplyDialer, mixProto.destReadBehavior)
  mixProto.codecs = @[MixProtocolID]
  mixProto.rng = rng
  mixProto.handler = proc(
      conn: Connection, proto: string
  ) {.async: (raises: [CancelledError]).} =
    await mixProto.handleMixNodeConnection(conn)

proc new*(
    T: typedesc[MixProtocol],
    mixNodeInfo: MixNodeInfo,
    pubNodeInfo: Table[PeerId, MixPubInfo],
    switch: Switch,
    tagManager: TagManager = TagManager.new(),
    rng: ref HmacDrbgContext = newRng(),
): T =
  let mixProto = new(T)
  mixProto.init(mixNodeInfo, pubNodeInfo, switch)
  mixProto

proc new*(
    T: typedesc[MixProtocol],
    index, numNodes: int,
    switch: Switch,
    nodeFolderInfoPath: string = ".",
    rng: ref HmacDrbgContext = newRng(),
): Result[T, string] =
  ## Constructs a new `MixProtocol` instance for the mix node at `index`,  
  ## loading its private info from `nodeInfo` and the public info of all other nodes from `pubInfo`.  
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
