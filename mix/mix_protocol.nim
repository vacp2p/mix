import chronicles, chronos, sequtils, strutils, os
import std/[strformat, sysrand]
import stew/endians2
import
  ./[
    config, curve25519, exit_connection, fragmentation, mix_message, mix_node, protocol,
    serialization, sphinx, tag_manager, utils,
  ]
import libp2p
import
  libp2p/
    [protocols/ping, protocols/protocol, stream/connection, stream/lpstream, switch]
from times import Time, getTime, toUnix, fromUnix, `-`, initTime, `$`, inMilliseconds

const MixProtocolID* = "/mix/1.0.0"

type MixProtocol* = ref object of LPProtocol
  mixNodeInfo: MixNodeInfo
  pubNodeInfo: Table[PeerId, MixPubInfo]
  switch: Switch
  tagManager: TagManager
  pHandler: ProtocolHandler

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

proc toUnixNs(t: Time): int64 =
  t.toUnix().int64 * 1_000_000_000 + times.nanosecond(t).int64

func byteToHex(b: byte): string = 
  b.toHex(2)
func bytesToHex(data: seq[byte]): string = 
  data.map(byteToHex).join(" ")


proc handleMixNodeConnection(
    mixProto: MixProtocol, conn: Connection
) {.async: (raises: [CancelledError]).} =
  var
    receivedBytes: seq[byte]
    metadata: seq[byte]
    fromPeerID: string
  try:
    metadata = await conn.readLp(21)
    receivedBytes = await conn.readLp(packetSize)
    fromPeerID = shortLog(conn.peerId)
  except Exception as e:
    error "Failed to read: ", err = e.msg
  finally:
    if conn != nil:
      try:
        await conn.close()
      except CatchableError as e:
        error "Failed to close incoming stream: ", err = e.msg

  let
    startTime = getTime()
    startTimeNs = toUnixNs(startTime)

  if metadata.len == 0 or receivedBytes.len == 0:
    return # No data, end of stream

  # Process the packet
  let (multiAddr, _, mixPrivKey, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)

  let processedPktRes =
    processSphinxPacket(receivedBytes, mixPrivKey, mixProto.tagManager)
  if processedPktRes.isErr:
    error "Failed to process Sphinx packet", err = processedPktRes.error
    return
  let (nextHop, delay, processedPkt, status) = processedPktRes.get()

  let ownPeerId = PeerId.init(multiAddr.split("/p2p/")[1]).valueOr:
    error "Failed to initialize my PeerId", err = error
    return


  let
    orig = uint64.fromBytesLE(metadata[0 ..< 8])
    msgid = uint64.fromBytesLE(metadata[13 ..< 21])
    myPeerId = shortLog(ownPeerId)
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
    trace "# Received: ", receiver = multiAddr, message = message
    await mixProto.pHandler(exitConn, protocol)

    if exitConn != nil:
      try:
        await exitConn.close()
      except CatchableError as e:
        error "Failed to close exit connection: ", err = e.msg

    let
      endTime = getTime()
      endTimeNs = toUnixNs(endTime)
      processingDelay = float(endTimeNs - startTimeNs) / 1_000_000.0
    
    info "Exit", msgid=msgid, fromPeerID=fromPeerID, toPeerID="None", myPeerId=myPeerId, orig=orig, current=startTimeNs, procDelay=processingDelay

  of Success:
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

    let
      endTime = getTime()
      endTimeNs = toUnixNs(endTime)
      processingDelay = float(endTimeNs - startTimeNs) / 1_000_000.0
      toPeerID = shortLog(peerId)

    info "Intermediate", msgid=msgid, fromPeerID=fromPeerID, toPeerID=toPeerID, myPeerId=myPeerId, orig=orig, current=startTimeNs, procDelay=processingDelay

    var nextHopConn: Connection
    try:
      nextHopConn = await mixProto.switch.dial(peerId, @[locationAddr], MixProtocolID)
      await nextHopConn.writeLp(metadata)
      await nextHopConn.writeLp(processedPkt)
    except CatchableError as e:
      error "Failed to dial next hop: ", err = e.msg
    finally:
      if nextHopConn != nil:
        try:
          await nextHopConn.close()
        except CatchableError as e:
          error "Failed to close outgoing stream: ", err = e.msg
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
  let
    startTime = getTime()
    startTimeNs = toUnixNs(startTime)

  let mixMsg = initMixMessage(msg, proto)

  let serialized = serializeMixMessage(mixMsg).valueOr:
    error "Serialization failed", err = error
    return

  let (multiAddr, _, _, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)

  let peerId = getPeerIdFromMultiAddr(multiAddr).valueOr:
    error "Failed to get peer id from multiaddress", err = error
    return

  let paddedMsg = padMessage(serialized, peerID)

  trace "# Sent: ", sender = multiAddr, message = msg, dest = destMultiAddr

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

  trace "# Sending to: ", multiaddr = multiAddrs[0]

  let ownPeerId = PeerId.init(multiAddr.split("/p2p/")[1]).valueOr:
    error "Failed to initialize my PeerId", err = error
    return

  let
    orig = uint64.fromBytesLE(msg[5 ..< 13])
    # whats happening bytes 8..13
    msgid = uint64.fromBytesLE(msg[13 ..< 21])
    toPeerID = shortLog(firstMixPeerId)
    myPeerId = shortLog(ownPeerId)
    endTime = getTime()
    endTimeNs = toUnixNs(endTime)
    processingDelay = float(endTimeNs - startTimeNs) / 1_000_000.0

  info "Sender", msgid=msgid, fromPeerID="None", toPeerID=toPeerID, myPeerId=myPeerId, orig=orig, current=startTimeNs, procDelay=processingDelay

  var nextHopConn: Connection
  try:
    nextHopConn =
      await mixProto.switch.dial(firstMixPeerId, @[firstMixAddr], @[MixProtocolID])
    await nextHopConn.writeLp(msg[0 ..< 21])
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
  mixProto.init()

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

method init*(mixProtocol: MixProtocol) {.gcsafe, raises: [].} =
  proc handle(conn: Connection, proto: string) {.async: (raises: [CancelledError]).} =
    await mixProtocol.handleMixNodeConnection(conn)

  mixProtocol.codecs = @[MixProtocolID]
  mixProtocol.handler = handle
