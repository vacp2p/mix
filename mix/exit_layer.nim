import std/[enumerate, strutils]
import chronicles, chronos, metrics
import libp2p, libp2p/[builders, stream/connection]
import ./[mix_metrics, exit_connection, serialization, utils]

type ProtocolHandler* = proc(conn: Connection, codec: string): Future[void] {.
  async: (raises: [CancelledError])
.}

type ExitLayer* = object
  switch: Switch
  pHandler: ProtocolHandler

proc callHandler(
    switch: Switch, conn: Connection, codec: string
): Future[void] {.async: (raises: [CatchableError]).} =
  for index, handler in enumerate(switch.ms.handlers):
    if codec in handler.protos:
      await handler.protocol.handler(conn, codec)
      return
  error "Handler doesn't exist", codec = codec

proc init*(T: typedesc[ExitLayer], switch: Switch): T =
  ExitLayer(
    switch: switch,
    pHandler: proc(
        conn: Connection, codec: string
    ): Future[void] {.async: (raises: [CancelledError]).} =
      try:
        await callHandler(switch, conn, codec)
      except CatchableError as e:
        error "Error during execution of MixProtocol handler: ", err = e.msg
    ,
  )

proc runHandler(
    self: ExitLayer, codec: string, message: seq[byte]
) {.async: (raises: [CancelledError]).} =
  let exitConn = MixExitConnection.new(message)

  await self.pHandler(exitConn, codec)

  try:
    await exitConn.close()
  except CatchableError as e:
    error "Failed to close exit connection: ", err = e.msg
  return

proc onMessage*(
    self: ExitLayer, codec: string, message: seq[byte], nextHop: Hop
) {.async: (raises: [CancelledError]).} =
  if nextHop == Hop():
    trace "onMessage - exit is destination", codec, message
    await self.runHandler(codec, message)
    return

  # Forward to destination
  let destBytes = getHop(nextHop)

  let fullAddrStr = bytesToMultiAddr(destBytes).valueOr:
    error "Failed to convert bytes to multiaddress", err = error
    mix_messages_error.inc(labelValues = ["ExitLayer", "INVALID_DEST"])
    return

  let parts = fullAddrStr.split("/p2p/")
  if parts.len != 2:
    error "Invalid multiaddress format", parts
    mix_messages_error.inc(labelValues = ["ExitLayer", "INVALID_DEST"])
    return

  # Create MultiAddress and PeerId
  let locationAddr = MultiAddress.init(parts[0]).valueOr:
    error "Failed to parse location multiaddress: ", err = error
    mix_messages_error.inc(labelValues = ["ExitLayer", "INVALID_DEST"])
    return

  let peerId = PeerId.init(parts[1]).valueOr:
    error "Failed to initialize PeerId", err = error
    mix_messages_error.inc(labelValues = ["ExitLayer", "INVALID_DEST"])
    return

  trace "onMessage - exit is not destination", peerId, locationAddr, codec, message

  var destConn: Connection
  try:
    destConn = await self.switch.dial(peerId, @[locationAddr], codec)
    await destConn.writeLp(message)
    #TODO: When response is implemented, we can read the response here
  except CatchableError as e:
    error "Failed to dial next hop: ", err = e.msg
    mix_messages_error.inc(labelValues = ["ExitLayer", "DIAL_FAILED"])
  finally:
    if not destConn.isNil:
      await destConn.close()
