import std/[enumerate, strutils]
import chronicles, chronos, metrics
import libp2p, libp2p/[builders, stream/connection]
import
  ./[
    mix_metrics, exit_connection, reply_connection, serialization, utils # fragmentation
  ]

type OnReplyDialer* =
  proc(surb: SURB, message: seq[byte]) {.async: (raises: [CancelledError]).}

type ProtocolHandler* = proc(conn: Connection, codec: string): Future[void] {.
  async: (raises: [CancelledError])
.}

type fwdBehaviorCb* = proc(conn: Connection, msg: seq[byte]): Future[seq[byte]] {.
  async: (raises: [CancelledError, LPStreamError])
.}

type ExitLayer* = object
  switch: Switch
  pHandler: ProtocolHandler
  onReplyDialer: OnReplyDialer
  fwdRWBehavior: TableRef[string, fwdBehaviorCb]

proc callHandler(
    switch: Switch, conn: Connection, codec: string
): Future[void] {.async: (raises: [CatchableError]).} =
  for index, handler in enumerate(switch.ms.handlers):
    if codec in handler.protos:
      await handler.protocol.handler(conn, codec)
      return

  error "Handler doesn't exist", codec = codec

proc init*(
    T: typedesc[ExitLayer],
    switch: Switch,
    onReplyDialer: OnReplyDialer,
    fwdRWBehavior: TableRef[string, fwdBehaviorCb],
): T =
  ExitLayer(
    switch: switch,
    onReplyDialer: onReplyDialer,
    fwdRWBehavior: fwdRWBehavior,
    pHandler: proc(
        conn: Connection, codec: string
    ): Future[void] {.async: (raises: [CancelledError]).} =
      try:
        await callHandler(switch, conn, codec)
      except CatchableError as e:
        error "Error during execution of MixProtocol handler: ", err = e.msg
    ,
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

  echo "\e[0;31mREPLYING>>>>>>>>>>>>>>>>>>>>>>>>>", response, "\e[0m"
  let replyConn = MixReplyConnection.new(surbs, self.replyDialerCbFactory())
  defer:
    if not replyConn.isNil:
      await replyConn.close()
  try:
    await replyConn.writeLp(response)
  except LPStreamError as exc:
    error "could not reply", description = exc.msg
    mix_messages_error.inc(labelValues = ["ExitLayer", "REPLY_FAILED"])

proc runHandler(
    self: ExitLayer, codec: string, message: seq[byte], surbs: seq[SURB]
) {.async: (raises: [CancelledError]).} =
  echo "Exit is handling request >>>>"
  let exitConn = MixExitConnection.new(message)
  defer:
    if not exitConn.isNil:
      await exitConn.close()

  await self.pHandler(exitConn, codec)

  if surbs.len != 0:
    let response = exitConn.getResponse()
    await self.reply(surbs, response)

proc onMessage*(
    self: ExitLayer, codec: string, message: seq[byte], nextHop: Hop, surbs: seq[SURB]
) {.async: (raises: [CancelledError]).} =
  if nextHop == Hop():
    trace "onMessage - exit is destination", codec, message
    await self.runHandler(codec, message, surbs)
    return

  echo "\e[0;32m>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo ">>>>>>>>    REPLYING      >>>>>>>>"
  echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\e[0m"

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

  if not self.fwdRWBehavior.hasKey(codec):
    error "No fwdRWBehavior for codec", codec
    return

  var behaviorCb: fwdBehaviorCb
  try:
    behaviorCb = self.fwdRWBehavior[codec]
  except KeyError:
    doAssert false, "checked with HasKey"

  var destConn: Connection
  var response: seq[byte]
  try:
    echo "EXIT IS DIALING: ", peerId, locationAddr
    destConn = await self.switch.dial(peerId, @[locationAddr], codec)
    response = await behaviorCb(destConn, message)
  except CatchableError as e:
    error "Failed to dial next hop: ", err = e.msg
    mix_messages_error.inc(labelValues = ["ExitLayer", "DIAL_FAILED"])
    return
  finally:
    if not destConn.isNil:
      await destConn.close()

  await self.reply(surbs, response)
