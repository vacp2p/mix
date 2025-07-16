import chronos, std/enumerate, strutils
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
  WakuLightPushProtocol = "/vac/waku/lightpush/3.0.0"
    #TODO: fix this hardcoding, for now doing it as importing codecs from waku causses various build errors.
  OtherProtocol = "other" # Placeholder for other protocols

type ProtocolHandler* = proc(conn: Connection, proto: ProtocolType): Future[void] {.
  async: (raises: [CancelledError])
.}

proc fromString*(T: type ProtocolType, proto: string): ProtocolType =
  try:
    parseEnum[ProtocolType](proto)
  except ValueError:
    ProtocolType.OtherProtocol

# TODO: this is temporary while I attempt to extract protocol specific logic from mix
func shouldFwd*(proto: ProtocolType): bool =
  return proto == GossipSub12 or proto == GossipSub11 or proto == GossipSub10

method callHandler*(
    switch: Switch, conn: Connection, proto: ProtocolType
): Future[void] {.base, async.} =
  let codec = $proto
  for index, handler in enumerate(switch.ms.handlers):
    if codec in handler.protos:
      await handler.protocol.handler(conn, codec)
      return
  error "Handler doesn't exist", codec = codec
