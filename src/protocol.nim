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
  OtherProtocol = "other" # Placeholder for other protocols

type ProtocolHandler* = proc(conn: Connection, proto: ProtocolType): Future[void] {.
  async: (raises: [CancelledError])
.}

proc fromString*(T: type ProtocolType, proto: string): ProtocolType =
  try:
    parseEnum[ProtocolType](proto)
  except ValueError:
    ProtocolType.OtherProtocol

method callHandler*(
    switch: Switch, conn: Connection, proto: ProtocolType
): Future[void] {.base, async.} =
  let codec = $proto
  for index, handler in enumerate(switch.ms.handlers):
    if codec in handler.protos:
      await handler.protocol.handler(conn, codec)
      return
  error "Handler doesn't exist", codec = codec
