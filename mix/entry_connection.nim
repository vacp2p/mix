import hashes, chronos, std/options, stew/byteutils
import libp2p/stream/connection
import ./protocol, ./mix_protocol

type MixDialer* = proc(
  msg: seq[byte],
  proto: ProtocolType,
  destMultiAddr: Option[MultiAddress],
  destPeerId: Option[PeerId],
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).}

type MixEntryConnection* = ref object of Connection
  destMultiAddr: Option[MultiAddress]
  destPeerId: Option[PeerId]
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
  let length = msg.len().uint64
  var
    vbytes: seq[byte] = @[]
    value = length

  while value >= 128:
    vbytes.add(byte((value and 127) or 128))
    value = value shr 7
  vbytes.add(byte(value))

  var buf = newSeqUninit[byte](msg.len() + vbytes.len)
  buf[0 ..< vbytes.len] = vbytes.toOpenArray(0, vbytes.len - 1)
  buf[vbytes.len ..< buf.len] = msg
  self.mixDialer(@buf, self.proto, self.destMultiAddr, self.destPeerId)

method writeLp*(
    self: MixEntryConnection, msg: string
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.writeLp(msg.toOpenArrayByte(0, msg.high))

method shortLog*(self: MixEntryConnection): string {.base, raises: [].} =
  "[MixEntryConnection] Destination: " & $self.destMultiAddr & "/p2p/" & $self.destPeerId

method initStream*(self: MixEntryConnection) {.raises: [].} =
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
    destPeerId: Option[PeerId],
    proto: ProtocolType,
    sendFunc: MixDialer,
): MixEntryConnection {.raises: [].} =
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

proc newConn*(
    T: typedesc[MixEntryConnection],
    destMultiAddr: string,
    destPeerId: PeerId,
    proto: ProtocolType,
    mixproto: MixProtocol,
): MixEntryConnection {.raises: [].} =
  #let destPeerId = getPeerIdFromMultiAddr(destMultiAddr).get()

  let maddr = MultiAddress.init(destMultiAddr).get()

  var sendDialerFunc = proc(
      msg: seq[byte],
      proto: ProtocolType,
      destMultiAddr: Option[MultiAddress],
      destPeerId: Option[PeerId],
  ): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
    try:
      await mixproto.anonymizeLocalProtocolSend(msg, proto, destMultiAddr, destPeerId)
    except CatchableError as e:
      error "Error during execution of sendThroughMixnet: ", err = e.msg
    return

  let instance = T(
    destMultiAddr: some(maddr),
    destPeerId: some(destPeerId),
    proto: proto,
    mixDialer: sendDialerFunc,
  )

  when defined(libp2p_agents_metrics):
    instance.shortAgent = connection.shortAgent

  instance
