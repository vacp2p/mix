import chronos
import config, curve25519, mix_node, serialization, sphinx, tag_manager, utils
import libp2p
import libp2p/[protocols/ping, protocols/protocol, stream/connection, stream/lpstream, switch]
import os, strutils

const MixProtocolID = "/mix/proto/1.0.0"

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

proc handleMixNodeConnection(mixProto: MixProtocol, conn: Connection) {.async.} =
  while true:
    var receivedBytes = await conn.readLp(packetSize)
    
    if receivedBytes.len == 0:
      break  # No data, end of stream

    # Process the packet
    let (_, _, mixPrivKey, _, _) = getMixNodeInfo(mixProto.mixNodeInfo)
    let (nextHop, delay, processedPkt, status) = processSphinxPacket(receivedBytes, mixPrivKey, mixProto.tagManager)

    case status:
    of Success:
      if (nextHop == Hop()) and (delay == @[]):
        # This is the exit node, forward to local ping protocol instance
        try:
          let peerInfo = mixProto.switch.peerInfo
          let pingStream = await mixProto.switch.dial(peerInfo.peerId, peerInfo.addrs, PingCodec)
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
  
proc new*(T: typedesc[MixProtocol], index, numNodes: int, switch: Switch): T =
  let mixNodeInfo = loadMixNodeInfo(index)
  let pubNodeInfo = loadAllButIndexMixPubInfo(index, numNodes)
  let tagManager = initTagManager()
  
  proc handle(conn: Connection, proto: string) {.async.} =
    let remotePeerId = conn.peerId

    if isMixNode(remotePeerId, pubNodeInfo):
      await handleMixNodeConnection(mixProto, conn)

  result = T(
    codecs: @[MixProtocolID],
    handler: handle,
    mixNodeInfo: mixNodeInfo,
    pubNodeInfo: pubNodeInfo,
    switch: switch,
    tagManager: tagManager
  )

