import chronos
import config, curve25519, serialization, sphinx, tag_manager
import libp2p
import libp2p/protocols/protocol
import libp2p/stream/connection
import os, strutils

const MixProtocolID = "/mix/proto/1.0.0"

type
  MixProtocol* = ref object of LPProtocol
    privateKey: FieldElement
    publicKey: FieldElement
    switch: Switch
    tagManager: TagManager

proc new*(T: typedesc[MixProtocol], switch: Switch): T =
  let (privateKey, publicKey) = generateKeyPair()
  let tagManager = initTagManager()
  
  proc handle(conn: Connection, proto: string) {.async.} =
    var mixProto = cast[MixProtocol](conn.protocol)
    while true:
      var receivedBytes = await conn.readLp(packetSize)
      
      if receivedBytes.len == 0:
        break  # No data, end of stream

      while receivedBytes.len >= packetSize:
        let packet = receivedBytes[0..packetSize-1]
        receivedBytes = receivedBytes[packetSize..^1]  # Remove the processed packet

        # Process the packet
        var tm = mixProto.tagManager
        let (nextHop, delay, processedPkt, status) = processSphinxPacket(packet, mixProto.privateKey, tm)
        mixProto.tagManager = tm  # Update the tagManager after processing

        case status:
        of Success:
          if not ((nextHop == Hop()) and (delay == @[]) and (status == Success)):
            # Add delay
            let delayMillis = (delay[0].int shl 8) or delay[1].int
            await sleepAsync(milliseconds(delayMillis))

            # Forward to next hop
            let fullAddrStr = cast[string](getHop(nextHop))
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

  result = T(
    codecs: @[MixProtocolID],
    handler: handle,
    privateKey: privateKey,
    publicKey: publicKey,
    switch: switch,
    tagManager: tagManager
  )