import chronos, std/enumerate
import libp2p/[builders, protocols/ping, stream/connection]
import ../protocols/[noresp_ping]

const protocolTypeSize* = 2

type ProtocolType* = enum
  Ping = 0 # Represents the Ping protocol
  GossipSub = 1 # Represents the GossipSub protocol
  NoRespPing = 2 # Represents the custom NoRespPing protocol
  OtherProtocol = 3 # Placeholder for other protocols

type ProtocolHandler* =
  proc(conn: Connection, proto: ProtocolType): Future[void] {.async.}

proc protocolFromString*(proto: string): ProtocolType =
  case proto
  of PingCodec:
    return Ping
  of NoRespPingCodec:
    return NoRespPing
  else:
    return OtherProtocol

proc stringFromProtocol*(proto: ProtocolType): string =
  case proto
  of Ping:
    return PingCodec
  of NoRespPing:
    return NoRespPingCodec
  else:
    return "other"

method callHandler*(
    switch: Switch, conn: Connection, proto: ProtocolType
): Future[void] {.base, async.} =
  let codec = stringFromProtocol(proto)
  for index, handler in enumerate(switch.ms.handlers):
    if codec in handler.protos:
      await handler.protocol.handler(conn, codec)
      return
