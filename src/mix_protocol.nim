import chronicles, chronos, sequtils, strutils
import std/sysrand
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

type MixProtocol* = ref object of LPProtocol
  mixNodeInfo: MixNodeInfo
  pubNodeInfo: Table[PeerId, MixPubInfo]
  switch: Switch
  tagManager: TagManager
  pHandler: ProtocolHandler

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
  while true:
    var receivedBytes = await conn.readLp(packetSize)

    if receivedBytes.len == 0:
      break # No data, end of stream

    # Process the packet
    let (multiAddr, _, mixPrivKey, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)

    let processedPktRes =
      processSphinxPacket(receivedBytes, mixPrivKey, mixProto.tagManager)
    if processedPktRes.isErr:
      error "Failed to process Sphinx packet", err = processedPktRes.error
      return
    let (nextHop, delay, processedPkt, status) = processedPktRes.get()

    case status
    of Exit:
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
        (message, protocol) = getMixMessage(deserializedResult)
        exitConn = MixExitConnection.new(message)
      info "# Received: ", receiver = multiAddr, message = message
      await mixProto.pHandler(exitConn, protocol)
    of Success:
      info "# Intermediate: ", multiAddr = multiAddr
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
        nextHopConn = await mixProto.switch.dial(peerId, @[locationAddr], MixProtocolID)
        await nextHopConn.writeLp(processedPkt)
        await nextHopConn.close()
      except CatchableError as e:
        error "Failed to dial next hop: ", err = e.msg
    of Duplicate:
      discard
    of InvalidMAC:
      discard

proc anonymizeLocalProtocolSend*(
    mixProto: MixProtocol,
    msg: seq[byte],
    proto: ProtocolType,
    destMultiAddr: Option[MultiAddress],
    destPeerId: PeerId,
) {.async.} =
  let mixMsg = initMixMessage(msg, proto)

  let serialized = serializeMixMessage(mixMsg).valueOr:
    error "Serialization failed", err = error
    return

  let (multiAddr, _, _, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)

  let peerId = getPeerIdFromMultiAddr(multiAddr).valueOr:
    error "Failed to get peer id from multiaddress", err = error
    return

  let paddedMsg = padMessage(serialized, peerID)

  info "# Sent: ", sender = multiAddr, message = msg, dest = destMultiAddr

  var
    multiAddrs: seq[string] = @[]
    publicKeys: seq[FieldElement] = @[]
    hop: seq[Hop] = @[]
    delay: seq[seq[byte]] = @[]

  # Select L mix nodes at random
  let numMixNodes = mixProto.pubNodeInfo.len
  if numMixNodes < L:
    error "No. of public mix nodes less than path length."
    return

  var
    pubNodeInfoKeys = toSeq(mixProto.pubNodeInfo.keys)
    randPeerId: PeerId
    availableIndices = toSeq(0 ..< numMixNodes)
  for i in 0 ..< L:
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

  info "# Sending to: ", multiaddr = multiAddrs[0]

  var nextHopConn: Connection
  try:
    nextHopConn =
      await mixProto.switch.dial(firstMixPeerId, @[firstMixAddr], @[MixProtocolID])
    await nextHopConn.writeLp(sphinxPacket)
    await nextHopConn.close()
  except CatchableError as e:
    error "Failed to send message to next hop: ", err = e.msg

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

method init*(mixProtocol: MixProtocol) {.gcsafe, raises: [].} =
  proc handle(conn: Connection, proto: string) {.async.} =
    await mixProtocol.handleMixNodeConnection(conn)

  mixProtocol.codecs = @[MixProtocolID]
  mixProtocol.handler = handle

proc setCallback*(mixProto: MixProtocol, switch: Switch): void =
  var sendHandlerFunc = proc(
      conn: Connection, proto: ProtocolType
  ): Future[void] {.async.} =
    try:
      await callHandler(switch, conn, proto) # Call handler on the switch
    except CatchableError as e:
      error "Error during execution of MixProtocol handler: ", err = e.msg
    return
  mixProto.pHandler = sendHandlerFunc
