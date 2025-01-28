import chronicles, chronos, strutils
import std/sysrand
import
  config, curve25519, fragmentation, mix_message, mix_node, sequtils, serialization,
  sphinx, tag_manager, utils
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

proc loadMixNodeInfo*(index: int): Result[MixNodeInfo, string] =
  let readNodeRes = readMixNodeInfoFromFile(index)
  if readNodeRes.isErr:
    return err("Failed to load node info from file.")
  else:
    ok(readNodeRes.get())

proc loadAllButIndexMixPubInfo*(
    index, numNodes: int
): Result[Table[PeerId, MixPubInfo], string] =
  var pubInfoTable = initTable[PeerId, MixPubInfo]()
  for i in 0 ..< numNodes:
    if i != index:
      let pubInfoRes = readMixPubInfoFromFile(i)
      if pubInfoRes.isErr:
        return err("Failed to load pub info from file.")
      else:
        let
          pubInfo = pubInfoRes.get()
          (multiAddr, _, _) = getMixPubInfo(pubInfo)

        let peerIdRes = getPeerIdFromMultiAddr(multiAddr)
        if peerIdRes.isErr:
          return err("Failed to get peer id from multiaddress: " & peerIdRes.error)
        let peerId = peerIdRes.get()

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

proc sendMessage(
    mixProto: MixProtocol,
    message: seq[byte],
    destMultiAddr: MultiAddress,
    destPeerId: PeerId,
) {.async.} =
  var multiAddrs: seq[string] = @[]
  var publicKeys: seq[FieldElement] = @[]
  var hop: seq[Hop] = @[]
  var delay: seq[seq[byte]] = @[]

  # Select L mix nodes at random
  let numMixNodes = mixProto.pubNodeInfo.len
  assert numMixNodes > 0, "No public mix nodes available."

  var pubNodeInfoKeys = toSeq(mixProto.pubNodeInfo.keys)
  var randPeerId: PeerId
  var availableIndices = toSeq(0 ..< numMixNodes)
  for i in 0 ..< L:
    if i == L - 1:
      randPeerId = destPeerId
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

    # Extract multiaddress, mix public key, and hop
    let (multiAddr, mixPubKey, _) = getMixPubInfo(mixProto.pubNodeInfo[randPeerId])
    multiAddrs.add(multiAddr)
    publicKeys.add(mixPubKey)

    let multiAddrBytesRes = multiAddrToBytes(multiAddr)
    if multiAddrBytesRes.isErr:
      error "Failed to convert multiaddress to bytes", err = multiAddrBytesRes.error
      return

    hop.add(initHop(multiAddrBytesRes.get()))

    # Compute delay
    let cryptoRandomIntResult = cryptoRandomInt(3)
    if cryptoRandomIntResult.isErr:
      error "Failed to generate random number", err = cryptoRandomIntResult.error
      return
    let delayMilliSec = cryptoRandomIntResult.value
    delay.add(uint16ToBytes(uint16(delayMilliSec)))

  # Wrap in Sphinx packet
  let sphinxPacketRes = wrapInSphinxPacket(initMessage(message), publicKeys, delay, hop)
  if sphinxPacketRes.isErr:
    error "Failed to wrap in sphinx packet", err = sphinxPacketRes.error
    return
  let sphinxPacket = sphinxPacketRes.get()

  # Send the wrapped message to the first mix node in the selected path
  let firstMixNode = multiAddrs[0]
  var nextHopConn: Connection
  try:
    let peerIdRes = getPeerIdFromMultiAddr(firstMixNode)
    if peerIdRes.isErr:
      error "Failed to get peer id from multiaddress: ", err = peerIdRes.error
      return
    let peerId = peerIdRes.get()

    nextHopConn = await mixProto.switch.dial(
      peerId,
      @[MultiAddress.init(firstMixNode.split("/p2p/")[0]).get()],
      @[MixProtocolID],
    )
    await nextHopConn.writeLp(sphinxPacket)
    await sleepAsync(milliseconds(100))
  except CatchableError as e:
    error "Failed to send message to next hop: ", err = e.msg
  finally:
    if not nextHopConn.isNil:
      await nextHopConn.close()

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
    of Success:
      if (nextHop == Hop()) and (delay == @[]):
        # This is the exit node, forward to local protocol instance
        let msgChunkRes = deserializeMessageChunk(processedPkt)
        if msgChunkRes.isErr:
          error "Deserialization failed", err = msgChunkRes.error
          return
        let msgChunk = msgChunkRes.get()

        let unpaddedMsgRes = unpadMessage(msgChunk)
        if unpaddedMsgRes.isErr:
          error "Unpadding message failed", err = unpaddedMsgRes.error
          return
        let unpaddedMsg = unpaddedMsgRes.get()

        let deserializedResult = deserializeMixMessage(unpaddedMsg)
        if deserializedResult.isErr:
          error "Deserialization failed", err = deserializedResult.error
          return
        let
          mixMsg = deserializedResult.get()
          (message, protocol) = getMixMessage(mixMsg)
        info "# Received: ", receiver = multiAddr, message = cast[string](message)
      else:
        info "# Intermediate: ", multiAddr = multiAddr
        # Add delay
        let delayMillis = (delay[0].int shl 8) or delay[1].int
        await sleepAsync(milliseconds(delayMillis))

        # Forward to next hop
        let nextHopBytes = getHop(nextHop)

        let fullAddrStrRes = bytesToMultiAddr(nextHopBytes)
        if fullAddrStrRes.isErr:
          error "Failed to convert bytes to multiaddress", err = fullAddrStrRes.error
          return
        let fullAddrStr = fullAddrStrRes.get()

        let parts = fullAddrStr.split("/p2p/")
        if parts.len != 2:
          error "Invalid multiaddress format", parts = parts
          return

        let locationAddrStr = parts[0]
        let peerIdStr = parts[1]

        # Create MultiAddress and PeerId
        let locationAddrRes = MultiAddress.init(locationAddrStr)
        if locationAddrRes.isErr:
          error "Failed to parse location multiaddress: ", err = locationAddrRes.error
          return
        let locationAddr = locationAddrRes.get()

        let peerIdRes = PeerId.init(peerIdStr)
        if peerIdRes.isErr:
          error "Failed to initialize PeerId", err = peerIdRes.error
          return
        let peerId = peerIdRes.get()

        var nextHopConn: Connection
        try:
          nextHopConn =
            await mixProto.switch.dial(peerId, @[locationAddr], MixProtocolID)
          await nextHopConn.writeLp(processedPkt)
        except CatchableError as e:
          error "Failed to dial next hop: ", err = e.msg
    of Duplicate:
      discard
    of InvalidMAC:
      discard
    of InvalidPoW:
      discard

  # Close the current connection after processing
  await conn.close()

proc anonymizeLocalProtocolSend*(
    mixProto: MixProtocol,
    mixMsg: seq[byte],
    destMultiAddr: MultiAddress,
    destPeerId: PeerId,
) {.async.} =
  # Pad the incoming message
  # ToDo: Split large messages
  let (multiAddr, _, _, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)

  let peerIdRes = getPeerIdFromMultiAddr(multiAddr)
  if peerIdRes.isErr:
    error "Failed to get peer id from multiaddress", err = peerIdRes.error
    return
  let peerId = peerIdRes.get()

  let paddedMsg = padMessage(mixMsg, peerID)

  let serializedRes = serializeMessageChunk(paddedMsg)
  if serializedRes.isErr:
    error "Failed to serialize padded message", err = serializedRes.error
    return

  info "# Sent: ", sender = multiAddr, message = cast[string](mixMsg)
  await sendMessage(mixProto, serializedRes.value, destMultiAddr, destPeerId)

proc new*(
    T: typedesc[MixProtocol], index, numNodes: int, switch: Switch
): Result[T, string] =
  let mixNodeInfoRes = loadMixNodeInfo(index)
  if mixNodeInfoRes.isErr:
    return err("Failed to load mix node info for index " & $index)

  let pubNodeInfoRes = loadAllButIndexMixPubInfo(index, numNodes)
  if pubNodeInfoRes.isErr:
    return err("Failed to load mix pub info for index " & $index)

  let mixProto = T(
    mixNodeInfo: mixNodeInfoRes.value,
    pubNodeInfo: pubNodeInfoRes.value,
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
