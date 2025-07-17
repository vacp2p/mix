import hashes, chronos, stew/byteutils
import libp2p/stream/connection
import std/options
import ./protocol, ./mix_node, ./mix_protocol

type MixDialer* = proc(
  msg: seq[byte],
  proto: ProtocolType,
  destMultiAddr: Option[MultiAddress],
  destPeerId: PeerId,
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).}

type MixEntryConnection* = ref object of Connection
  destMultiAddr: Option[MultiAddress]
  destPeerId: PeerId
  proto: ProtocolType
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
  self.mixDialer(@msg, self.proto, self.destMultiAddr, self.destPeerId)

proc write*(
    self: MixEntryConnection, msg: string
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.write(msg.toBytes())

method writeLp*(
    self: MixEntryConnection, msg: openArray[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  var buf: seq[byte]

  if shouldFwd(self.proto):
    buf = @msg
  else:
    let length = msg.len().uint64
    var
      vbytes: seq[byte] = @[]
      value = length

    while value >= 128:
      vbytes.add(byte((value and 127) or 128))
      value = value shr 7
    vbytes.add(byte(value))

    buf = newSeqUninitialized[byte](msg.len() + vbytes.len)
    buf[0 ..< vbytes.len] = vbytes.toOpenArray(0, vbytes.len - 1)
    buf[vbytes.len ..< buf.len] = msg

  self.mixDialer(@buf, self.proto, self.destMultiAddr, self.destPeerId)

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

proc new*(
    T: typedesc[MixEntryConnection],
    destMultiAddr: Option[MultiAddress],
    destPeerId: PeerId,
    proto: ProtocolType,
    sendFunc: MixDialer,
): MixEntryConnection =
  let instance = T(
    destMultiAddr: destMultiAddr,
    destPeerId: destPeerId,
    proto: proto,
    mixDialer: sendFunc,
  )

  when defined(libp2p_agents_metrics):
    instance.shortAgent = connection.shortAgent

  instance

when defined(libp2p_agents_metrics):
  proc setShortAgent*(self: MixEntryConnection, shortAgent: string) =
    discard
