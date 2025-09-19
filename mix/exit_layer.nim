import chronicles, chronos, metrics
from times import getTime, toUnixFloat, `-`, initTime, `$`, inMilliseconds, Time
import libp2p, libp2p/[builders, stream/connection]
import ./[mix_metrics, reply_connection, serialization]

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

proc onMessage*(
    self: ExitLayer,
    codec: string,
    message: seq[byte],
    destAddr: MultiAddress,
    destPeerId: PeerId,
    surbs: seq[SURB],
) {.async: (raises: [CancelledError]).} =
  var destConn: Connection
  var response: seq[byte]
  try:
    let currTime0 = getTime()
    let currTimeNano0 = int64(toUnixFloat(currTime0) * 1_000_000_000)
    info "getting destConn", now = currTimeNano0
    destConn = await self.switch.dial(destPeerId, @[destAddr], codec)
    let currTime1 = getTime()
    let currTimeNano1 = int64(toUnixFloat(currTime1) * 1_000_000_000)
    info "got destConn", now = currTimeNano1
    await destConn.write(message)
    let currTime2 = getTime()
    let currTimeNano2 = int64(toUnixFloat(currTime2) * 1_000_000_000)
    info "destConn write done", now = currTimeNano2

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
      let currTime3 = getTime()
      let currTimeNano3 = int64(toUnixFloat(currTime3) * 1_000_000_000)
      info "behaviorCb done", now = currTimeNano3
  except CatchableError as e:
    error "Failed to dial next hop: ", err = e.msg
    mix_messages_error.inc(labelValues = ["ExitLayer", "DIAL_FAILED"])
    return
  finally:
    if not destConn.isNil:
      await destConn.close()

  await self.reply(surbs, response)
  let currTime4 = getTime()
  let currTimeNano4 = int64(toUnixFloat(currTime4) * 1_000_000_000)
  info "reply done", now = currTimeNano4
