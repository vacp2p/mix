import chronos, strutils
import
  libp2p/[builders, protocols/ping, protocols/pubsub/gossipsub/types, stream/connection]
import ./protocols/noresp_ping

const protocolTypeSize* = 2

type ProtocolType* = enum
  PingProtocol = PingCodec
  GossipSub12 = GossipSubCodec_12
  GossipSub11 = GossipSubCodec_11
  GossipSub10 = GossipSubCodec_10
  NoRespPing = NoRespPingCodec
  WakuLightPushProtocol = "/vac/waku/lightpush/3.0.0"
    #TODO: fix this hardcoding, for now doing it as importing codecs from waku causses various build errors.
  OtherProtocol = "other" # Placeholder for other protocols

proc fromString*(T: type ProtocolType, proto: string): ProtocolType =
  try:
    parseEnum[ProtocolType](proto)
  except ValueError:
    ProtocolType.OtherProtocol
