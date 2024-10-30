import hashes, chronos
import libp2p/stream/connection

type MixnetConnectionAdapter* = ref object of Connection
  connection: Connection

method connection*(
    self: MixnetConnectionAdapter
): Connection {.gcsafe, base, raises: [].} =
  self.connection

method join*(
    self: MixnetConnectionAdapter
): Future[void] {.async: (raises: [CancelledError], raw: true), public.} =
  self.connection.join()

method readExactly*(
    self: MixnetConnectionAdapter, pbytes: pointer, nbytes: int
): Future[void] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readExactly(pbytes, nbytes)

method readLine*(
    self: MixnetConnectionAdapter, limit = 0, sep = "\r\n"
): Future[string] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readLine(limit, sep)

method readVarint*(
    self: MixnetConnectionAdapter
): Future[uint64] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readVarint()

method readLp*(
    self: MixnetConnectionAdapter, maxSize: int
): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readLp(maxSize)

method writeLp*(
    self: MixnetConnectionAdapter, msg: openArray[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.connection.writeLp(msg)

method writeLp*(
    self: MixnetConnectionAdapter, msg: string
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.connection.writeLp(msg.toOpenArrayByte(0, msg.high))

# proc timeoutMonitor(self: MixnetConnectionAdapter) {.async: (raises: []).} =
#   self.connection.timeoutMonitor()

method shortLog*(self: MixnetConnectionAdapter): string {.raises: [].} =
  "[MixnetConnectionAdapter] " & self.connection.shortLog()

method initStream*(self: MixnetConnectionAdapter) =
  self.connection.initStream()

method closeImpl*(self: MixnetConnectionAdapter): Future[void] {.async: (raises: []).} =
  self.connection.closeImpl()

func hash*(self: MixnetConnectionAdapter): Hash =
  self.connection.hash()

proc new*(
    T: typedesc[MixnetConnectionAdapter], connection: Connection
): MixnetConnectionAdapter =
  let instance = T(
    connection: connection,
    activity: connection.activity,
    timeout: connection.timeout,
    # timerTaskFut: connection.timerTaskFut,
    timeoutHandler: connection.timeoutHandler,
    peerId: connection.peerId,
    observedAddr: connection.observedAddr,
    protocol: connection.protocol,
    transportDir: connection.transportDir,
  )

  when defined(libp2p_agents_metrics):
    instance.shortAgent = connection.shortAgent

  instance

# proc pollActivity(self: MixnetConnectionAdapter): Future[bool] {.async: (raises: []).} =
#   self.connection.pollActivity()

# proc timeoutMonitor(self: MixnetConnectionAdapter) {.async: (raises: []).} =
#   self.connection.timeoutMonitor()

method getWrapped*(self: MixnetConnectionAdapter): Connection =
  self.connection.getWrapped()

when defined(libp2p_agents_metrics):
  proc setShortAgent*(self: MixnetConnectionAdapter, shortAgent: string) =
    self.connection.setShortAgent(shortAgent)
