import os, std/asyncdispatch, strutils
import libp2p
import libp2p/[switch, 
                stream/connection,
                protocols/protocol,
                crypto/crypto,
                peerinfo,
                multiaddress,
                builders,
                peerid]
import config, curve25519, network_manager, serialization, sphinx

const MixProtocolID = "/mix/1.0.0"

type
  MixProto = ref object of LPProtocol
    privateKey: FieldElement
    publicKey: FieldElement
    nm: NetworkManager

proc newMixProto(nm: NetworkManager, privateKey, publicKey: FieldElement): MixProto =
  result = MixProto(nm: nm, privateKey: privateKey, publicKey: publicKey)
  proc handle(conn: Connection, proto: string) {.async.} =
    while true:
      var receivedBytes = await conn.readLp(packetSize)
      
      if receivedBytes.len == 0:
        break  # No data, end of stream

      while receivedBytes.len >= packetSize:
        let packet = receivedBytes[0..packetSize-1]
        receivedBytes = receivedBytes[packetSize..^1]  # Remove the processed packet

        # Process the packet
        let (nextHop, delay, processedPkt, status) = processSphinxPacket(packet, privateKey)

        case status:
        of Success:
          if not ((nextHop == Hop()) and (delay == @[]) and (status == Success)):
            # Add delay
            let delayMillis = (delay[0] shl 8) or delay[1]
            sleep(int(delayMillis))

            # Forward to next hop
            let multiAddr = cast[string](getHop(nextHop))
            let nextHopConn = await dialToNextHop(nm, nextHopAddr, MixProtocolID)
            await nextHopConn.writeLp(processedPkt)
            await nextHopConn.close()

        of Duplicate:
          discard
        of InvalidMAC:
          discard
        of InvalidPoW:
          discard

    # Close the current connection after processing
    await conn.close()