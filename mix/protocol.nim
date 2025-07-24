import chronos, std/enumerate
import
  libp2p/[builders, protocols/ping, protocols/pubsub/gossipsub/types, stream/connection]

type ProtocolHandler* = proc(conn: Connection, codec: string): Future[void] {.
  async: (raises: [CancelledError])
.}

# TODO: this is temporary while I attempt to extract protocol specific logic from mix
func destIsExit*(proto: string): bool =
  return
    not (
      proto == GossipSubCodec_12 or proto == GossipSubCodec_11 or
      proto == GossipSubCodec_10
    )

method callHandler*(
    switch: Switch, conn: Connection, codec: string
): Future[void] {.base, async.} =
  for index, handler in enumerate(switch.ms.handlers):
    if codec in handler.protos:
      await handler.protocol.handler(conn, codec)
      return
  error "Handler doesn't exist", codec = codec
