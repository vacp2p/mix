import hashes, chronos
import libp2p/stream/connection

type MixMiddleConnection* = ref object of Connection
  connection: Connection

method join*(
    self: MixMiddleConnection
): Future[void] {.async: (raises: [CancelledError], raw: true), public.} =
  self.connection.join()

method readExactly*(
    self: MixMiddleConnection, pbytes: pointer, nbytes: int
): Future[void] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readExactly(pbytes, nbytes)

method readLine*(
    self: MixMiddleConnection, limit = 0, sep = "\r\n"
): Future[string] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readLine(limit, sep)

method readVarint*(
    self: MixMiddleConnection
): Future[uint64] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readVarint()

method readLp*(
    self: MixMiddleConnection, maxSize: int
): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readLp(maxSize)

method writeLp*(
    self: MixMiddleConnection, msg: openArray[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.connection.writeLp(msg)

method writeLp*(
    self: MixMiddleConnection, msg: string
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.connection.writeLp(msg.toOpenArrayByte(0, msg.high))

method shortLog*(self: MixMiddleConnection): string {.raises: [].} =
  "[MixMiddleConnection] " & self.connection.shortLog()

method initStream*(self: MixMiddleConnection) =
  self.connection.initStream()

method closeImpl*(self: MixMiddleConnection): Future[void] {.async: (raises: []).} =
  self.connection.closeImpl()

func hash*(self: MixMiddleConnection): Hash =
  self.connection.hash()

proc new*(
    T: typedesc[MixMiddleConnection],
    connection: Connection,
    address: Opt[MultiAddress] = Opt.none(Multiaddress),
    peerId: Opt[PeerId] = Opt.none(PeerId),
): MixMiddleConnection =
  let instance = T(
    connection: connection,
    activity: connection.activity,
    timeout: connection.timeout,
    timeoutHandler: connection.timeoutHandler,
    peerId: peerId.get(),
    observedAddr: address,
    protocol: connection.protocol,
    transportDir: connection.transportDir,
  )

  when defined(libp2p_agents_metrics):
    instance.shortAgent = connection.shortAgent

  instance

when defined(libp2p_agents_metrics):
  proc setShortAgent*(self: MixMiddleConnection, shortAgent: string) =
    discard
