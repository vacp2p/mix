import chronos, chronicles, std/enumerate
import libp2p/[builders, stream/connection]

type ProtocolHandler* = proc(conn: Connection, codec: string): Future[void] {.
  async: (raises: [CancelledError])
.}

method callHandler*(
    switch: Switch, conn: Connection, codec: string
): Future[void] {.base, async.} =
  for index, handler in enumerate(switch.ms.handlers):
    if codec in handler.protos:
      await handler.protocol.handler(conn, codec)
      return
  error "Handler doesn't exist", codec = codec
