import chronos, strutils
import
  libp2p/[builders, protocols/ping, protocols/pubsub/gossipsub/types, stream/connection]
import ./protocols/noresp_ping

const protocolTypeSize* = 2

type ProtocolType* = enum
  Ping = PingCodec
  GossipSub12 = GossipSubCodec_12
  GossipSub11 = GossipSubCodec_11
  GossipSub10 = GossipSubCodec_10
  NoRespPing = NoRespPingCodec
  OtherProtocol = "other" # Placeholder for other protocols

proc fromString*(T: type ProtocolType, proto: string): ProtocolType =
  try:
    parseEnum[ProtocolType](proto)
  except ValueError:
    ProtocolType.OtherProtocol
