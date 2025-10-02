import chronicles, chronos, metrics, std/[strutils]
import libp2p, libp2p/[builders, stream/connection]
import ./[mix_metrics, reply_connection, serialization, utils]

when defined(mix_experimental_exit_is_destination):
  import std/enumerate
  import ./exit_connection

type OnReplyDialer* =
  proc(surb: SURB, message: seq[byte]) {.async: (raises: [CancelledError]).}

## Callback type for reading responses from a destination connection
type destReadBehaviorCb* = proc(conn: Connection): Future[seq[byte]] {.
  async: (raises: [CancelledError, LPStreamError])
.}

type ExitLayer* = object
  switch: Switch
  onReplyDialer: OnReplyDialer
  destReadBehavior: TableRef[string, destReadBehaviorCb]

proc init*(
    T: typedesc[ExitLayer],
    switch: Switch,
    onReplyDialer: OnReplyDialer,
    destReadBehavior: TableRef[string, destReadBehaviorCb],
): T =
  ExitLayer(
    switch: switch, onReplyDialer: onReplyDialer, destReadBehavior: destReadBehavior
  )

proc replyDialerCbFactory(self: ExitLayer): MixReplyDialer =
  return proc(
      surbs: seq[SURB], msg: seq[byte]
  ): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
    try:
      var respFuts: seq[Future[void]] = @[]
      for surb in surbs:
        respFuts.add(self.onReplyDialer(surb, msg))
      await allFutures(respFuts)
    except CancelledError as e:
      raise e
    except CatchableError as e:
      error "Error during execution of reply: ", err = e.msg
    return

proc reply(
    self: ExitLayer, surbs: seq[SURB], response: seq[byte]
) {.async: (raises: [CancelledError]).} =
  if surbs.len == 0:
    return

  let replyConn = MixReplyConnection.new(surbs, self.replyDialerCbFactory())
  defer:
    if not replyConn.isNil:
      await replyConn.close()
  try:
    await replyConn.write(response)
  except LPStreamError as exc:
    error "could not reply", description = exc.msg
    mix_messages_error.inc(labelValues = ["ExitLayer", "REPLY_FAILED"])

when defined(mix_experimental_exit_is_destination):
  proc runHandler(
      self: ExitLayer, codec: string, message: seq[byte], surbs: seq[SURB]
  ) {.async: (raises: [CancelledError]).} =
    let exitConn = MixExitConnection.new(message)
    defer:
      if not exitConn.isNil:
        await exitConn.close()

      var hasHandler: bool = false
      for index, handler in enumerate(self.switch.ms.handlers):
        if codec in handler.protos:
          try:
            hasHandler = true
            await handler.protocol.handler(exitConn, codec)
          except CatchableError as e:
            error "Error during execution of MixProtocol handler: ", err = e.msg

      if not hasHandler:
        error "Handler doesn't exist", codec = codec
        return

      if surbs.len != 0:
        let response = exitConn.getResponse()
        await self.reply(surbs, response)

proc fwdRequest(
    self: ExitLayer,
    codec: string,
    message: seq[byte],
    destination: Hop,
    surbs: seq[SURB],
) {.async: (raises: [CancelledError]).} =
  if destination == Hop():
    error "no destination available"
    mix_messages_error.inc(labelValues = ["Exit", "NO_DESTINATION"])
    return

  let destBytes = getHop(destination)

  let fullAddrStr = bytesToMultiAddr(destBytes).valueOr:
    error "Failed to convert bytes to multiaddress", err = error
    mix_messages_error.inc(labelValues = ["Exit", "INVALID_DEST"])
    return

  let parts = fullAddrStr.split("/p2p/")
  if parts.len != 2:
    error "Invalid multiaddress format", parts
    mix_messages_error.inc(labelValues = ["Exit", "INVALID_DEST"])
    return

  # Create MultiAddress and PeerId
  let destAddr = MultiAddress.init(parts[0]).valueOr:
    error "Failed to parse location multiaddress: ", err = error
    mix_messages_error.inc(labelValues = ["Exit", "INVALID_DEST"])
    return

  let destPeerId = PeerId.init(parts[1]).valueOr:
    error "Failed to initialize PeerId", err = error
    mix_messages_error.inc(labelValues = ["Exit", "INVALID_DEST"])
    return

  var destConn: Connection
  var response: seq[byte]
  try:
    destConn = await self.switch.dial(destPeerId, @[destAddr], codec)
    await destConn.write(message)

    if surbs.len != 0:
      if not self.destReadBehavior.hasKey(codec):
        error "No destReadBehavior for codec", codec
        return

      var behaviorCb: destReadBehaviorCb
      try:
        behaviorCb = self.destReadBehavior[codec]
      except KeyError:
        doAssert false, "checked with HasKey"

      response = await behaviorCb(destConn)
  except CatchableError as e:
    error "Failed to dial next hop: ", err = e.msg
    mix_messages_error.inc(labelValues = ["ExitLayer", "DIAL_FAILED"])
    return
  finally:
    if not destConn.isNil:
      await destConn.close()

  await self.reply(surbs, response)

proc onMessage*(
    self: ExitLayer,
    codec: string,
    message: seq[byte],
    destination: Hop,
    surbs: seq[SURB],
) {.async: (raises: [CancelledError]).} =
  when defined(mix_experimental_exit_is_destination):
    if destination == Hop():
      trace "onMessage - exit is destination", codec, message
      await self.runHandler(codec, message, surbs)
    else:
      trace "onMessage - exist is not destination", codec, message
      await self.fwdRequest(codec, message, destination, surbs)
  else:
    await self.fwdRequest(codec, message, destination, surbs)
