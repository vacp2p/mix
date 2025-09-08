import std/strutils
import chronicles, chronos, metrics
import libp2p, libp2p/[builders, stream/connection]
import ./[mix_metrics, reply_connection, serialization, utils]

type OnReplyDialer* =
  proc(surb: SURB, message: seq[byte]) {.async: (raises: [CancelledError]).}

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

proc onMessage*(
    self: ExitLayer, codec: string, message: seq[byte], nextHop: Hop, surbs: seq[SURB]
) {.async: (raises: [CancelledError]).} =
  if nextHop == Hop():
    error "no destination available"
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
  var response: seq[byte]
  try:
    destConn = await self.switch.dial(peerId, @[locationAddr], codec)
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
