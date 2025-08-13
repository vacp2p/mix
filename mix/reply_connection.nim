import hashes, chronos, stew/byteutils, results, chronicles
import libp2p/stream/connection
import libp2p
import ./[serialization]
from fragmentation import dataSize

type MixReplyDialer* = proc(surbs: seq[SURB], msg: seq[byte]): Future[void] {.
  async: (raises: [CancelledError, LPStreamError], raw: true)
.}

type MixReplyConnection* = ref object of Connection
  surbs: seq[SURB]
  mixReplyDialer: MixReplyDialer

method readExactly*(
    self: MixReplyConnection, pbytes: pointer, nbytes: int
): Future[void] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise
    newException(LPStreamError, "readExactly not implemented for MixReplyConnection")

method readLine*(
    self: MixReplyConnection, limit = 0, sep = "\r\n"
): Future[string] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise newException(LPStreamError, "readLine not implemented for MixReplyConnection")

method readVarint*(
    self: MixReplyConnection
): Future[uint64] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise newException(LPStreamError, "readVarint not implemented for MixReplyConnection")

method readLp*(
    self: MixReplyConnection, maxSize: int
): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise newException(LPStreamError, "readLp not implemented for MixReplyConnection")

method write*(
    self: MixReplyConnection, msg: seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.mixReplyDialer(self.surbs, msg)

proc write*(
    self: MixReplyConnection, msg: string
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.write(msg.toBytes())

method writeLp*(
    self: MixReplyConnection, msg: openArray[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  if msg.len() > dataSize:
    let fut = newFuture[void]()
    fut.fail(
      newException(LPStreamError, "exceeds max msg size of " & $dataSize & " bytes")
    )
    return fut

  var
    vbytes: seq[byte] = @[]
    value = msg.len().uint64

  while value >= 128:
    vbytes.add(byte((value and 127) or 128))
    value = value shr 7
  vbytes.add(byte(value))

  var buf = newSeqUninitialized[byte](msg.len() + vbytes.len)
  buf[0 ..< vbytes.len] = vbytes.toOpenArray(0, vbytes.len - 1)
  buf[vbytes.len ..< buf.len] = msg

  self.mixReplyDialer(self.surbs, @buf)

method writeLp*(
    self: MixReplyConnection, msg: string
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.writeLp(msg.toOpenArrayByte(0, msg.high))

proc shortLog*(self: MixReplyConnection): string {.raises: [].} =
  "[MixReplyConnection]"

method initStream*(self: MixReplyConnection) =
  discard

method closeImpl*(
    self: MixReplyConnection
): Future[void] {.async: (raises: [], raw: true).} =
  let fut = newFuture[void]()
  fut.complete()
  return fut

func hash*(self: MixReplyConnection): Hash =
  hash($self.surbs)

when defined(libp2p_agents_metrics):
  proc setShortAgent*(self: MixReplyConnection, shortAgent: string) =
    discard

proc new*(
    T: typedesc[MixReplyConnection], surbs: seq[SURB], mixReplyDialer: MixReplyDialer
): T =
  let instance = T(surbs: surbs, mixReplyDialer: mixReplyDialer)

  when defined(libp2p_agents_metrics):
    instance.shortAgent = connection.shortAgent

  instance
