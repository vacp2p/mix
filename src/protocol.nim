import chronos, strutils
import
  libp2p/[builders, protocols/ping, protocols/pubsub/gossipsub/types, stream/connection]

const protocolTypeSize* = 2

type ProtocolType* = enum
  Ping = PingCodec
  GossipSub12 = GossipSubCodec_12
  GossipSub11 = GossipSubCodec_11
  GossipSub10 = GossipSubCodec_10
  OtherProtocol = "other" # Placeholder for other protocols

type ProtocolHandler* =
  proc(conn: Connection, proto: ProtocolType): Future[void] {.async.}

proc fromString*(T: type ProtocolType, proto: string): ProtocolType =
  try:
    parseEnum[ProtocolType](proto)
  except ValueError:
    ProtocolType.OtherProtocol
