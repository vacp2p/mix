import hashes, chronos, stew/byteutils, results
import libp2p/stream/connection
import ./mix_protocol

type MixDialer* = proc(
  msg: seq[byte], codec: string, destMultiAddr: Opt[MultiAddress], destPeerId: PeerId
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).}

type MixEntryConnection* = ref object of Connection
  destMultiAddr: Opt[MultiAddress]
  destPeerId: PeerId
  codec: string
  mixDialer: MixDialer

method readExactly*(
    self: MixEntryConnection, pbytes: pointer, nbytes: int
): Future[void] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise
    newException(LPStreamError, "readExactly not implemented for MixEntryConnection")

method readLine*(
    self: MixEntryConnection, limit = 0, sep = "\r\n"
): Future[string] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise newException(LPStreamError, "readLine not implemented for MixEntryConnection")

method readVarint*(
    self: MixEntryConnection
): Future[uint64] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise newException(LPStreamError, "readVarint not implemented for MixEntryConnection")

method readLp*(
    self: MixEntryConnection, maxSize: int
): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise newException(LPStreamError, "readLp not implemented for MixEntryConnection")

method write*(
    self: MixEntryConnection, msg: seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.mixDialer(msg, self.codec, self.destMultiAddr, self.destPeerId)

proc write*(
    self: MixEntryConnection, msg: string
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.write(msg.toBytes())

method writeLp*(
    self: MixEntryConnection, msg: openArray[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  let length = msg.len().uint64
  var
    vbytes: seq[byte] = @[]
    value = length

  while value >= 128:
    vbytes.add(byte((value and 127) or 128))
    value = value shr 7
  vbytes.add(byte(value))

  var buf = newSeqUninitialized[byte](msg.len() + vbytes.len)
  buf[0 ..< vbytes.len] = vbytes.toOpenArray(0, vbytes.len - 1)
  buf[vbytes.len ..< buf.len] = msg

  self.mixDialer(@buf, self.codec, self.destMultiAddr, self.destPeerId)

method writeLp*(
    self: MixEntryConnection, msg: string
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.writeLp(msg.toOpenArrayByte(0, msg.high))

proc shortLog*(self: MixEntryConnection): string {.raises: [].} =
  "[MixEntryConnection] Destination: " & $self.destMultiAddr & "/p2p/" & $self.destPeerId

method initStream*(self: MixEntryConnection) =
  discard

method closeImpl*(
    self: MixEntryConnection
): Future[void] {.async: (raises: [], raw: true).} =
  let fut = newFuture[void]()
  fut.complete()
  return fut

func hash*(self: MixEntryConnection): Hash =
  hash($self.destMultiAddr & "/p2p/" & $self.destPeerId)

when defined(libp2p_agents_metrics):
  proc setShortAgent*(self: MixEntryConnection, shortAgent: string) =
    discard

proc new*(
    T: typedesc[MixEntryConnection],
    srcMix: MixProtocol,
    destMultiAddr: Opt[MultiAddress],
    destPeerId: PeerId,
    mixDialer: MixDialer,
    codec: string,
): T =
  let instance = T(
    destMultiAddr: destMultiAddr,
    destPeerId: destPeerId,
    codec: codec,
    mixDialer: mixDialer,
  )

  when defined(libp2p_agents_metrics):
    instance.shortAgent = connection.shortAgent

  instance

proc new*(
    T: typedesc[MixEntryConnection],
    srcMix: MixProtocol,
    destMultiAddr: Opt[MultiAddress],
    destPeerId: PeerId,
    codec: string,
    exitNodeIsDestination: bool = false,
): T {.raises: [].} =
  var sendDialerFunc = proc(
      msg: seq[byte],
      codec: string,
      destMultiAddr: Opt[MultiAddress],
      destPeerId: PeerId,
  ): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
    try:
      await srcMix.anonymizeLocalProtocolSend(
        msg, codec, destMultiAddr, destPeerId, exitNodeIsDestination
      )
    except CatchableError as e:
      error "Error during execution of anonymizeLocalProtocolSend: ", err = e.msg
    return

  T.new(srcMix, destMultiAddr, destPeerId, sendDialerFunc, codec)
