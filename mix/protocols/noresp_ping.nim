{.push raises: [].}

import chronos, chronicles
import bearssl/rand
import
  libp2p/[
    protobuf/minprotobuf,
    peerinfo,
    stream/connection,
    peerid,
    crypto/crypto,
    multiaddress,
    protocols/protocol,
  ]

logScope:
  topics = "libp2p anonping"

const
  NoRespPingCodec* = "/anonping/1.0.0"
  NoRespPingSize = 32

type
  NoRespPingHandler* {.public.} =
    proc(peer: PeerId): Future[void] {.gcsafe, raises: [].}

  NoRespPing* = ref object of LPProtocol
    noRespPingHandler*: NoRespPingHandler
    rng: ref HmacDrbgContext

proc new*(
    T: typedesc[NoRespPing],
    handler: NoRespPingHandler = nil,
    rng: ref HmacDrbgContext = newRng(),
): T {.public.} =
  let noRespPing = NoRespPing(noRespPingHandler: handler, rng: rng)
  noRespPing.init()
  noRespPing

method init*(p: NoRespPing) =
  proc handle(conn: Connection, proto: string) {.async.} =
    try:
      trace "handling ping"
      var buf: array[NoRespPingSize, byte]
      await conn.readExactly(addr buf[0], NoRespPingSize)
      info "received ping: ", ping = @buf
      if not isNil(p.noRespPingHandler):
        await p.noRespPingHandler(conn.peerId)
    except CatchableError as exc:
      trace "exception in ping handler", description = exc.msg, conn

  p.handler = handle
  p.codec = NoRespPingCodec

proc noRespPing*(p: NoRespPing, conn: Connection): Future[seq[byte]] {.async, public.} =
  trace "initiating ping"
  var randomBuf: array[NoRespPingSize, byte]
  hmacDrbgGenerate(p.rng[], randomBuf)
  trace "sending ping"
  await conn.write(@randomBuf)
  trace "sent ping: ", ping = @randomBuf
  return @randomBuf
