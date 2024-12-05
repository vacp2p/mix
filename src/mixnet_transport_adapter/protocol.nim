import chronos, std/enumerate
import libp2p/[builders, protocols/ping, stream/connection]

const protocolTypeSize* = 2

type ProtocolType* = enum
  Ping = 0 # Represents the Ping protocol
  GossipSub = 1 # Represents the GossipSub protocol
  OtherProtocol = 2 # Placeholder for other protocols

type ProtocolHandler* =
  proc(conn: Connection, proto: ProtocolType): Future[void] {.async.}

proc protocolFromString*(proto: string): ProtocolType =
  case proto
  of PingCodec:
    return Ping
  else:
    return OtherProtocol

proc stringFromProtocol*(proto: ProtocolType): string =
  case proto
  of Ping:
    return PingCodec
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
