import hashes, chronos
import libp2p/stream/connection

type MixPhysicalConnection* = ref object of Connection
  connection: Connection

method join*(
    self: MixPhysicalConnection
): Future[void] {.async: (raises: [CancelledError], raw: true), public.} =
  self.connection.join()

method readExactly*(
    self: MixPhysicalConnection, pbytes: pointer, nbytes: int
): Future[void] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readExactly(pbytes, nbytes)

method readLine*(
    self: MixPhysicalConnection, limit = 0, sep = "\r\n"
): Future[string] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readLine(limit, sep)

method readVarint*(
    self: MixPhysicalConnection
): Future[uint64] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readVarint()

method readLp*(
    self: MixPhysicalConnection, maxSize: int
): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readLp(maxSize)

method writeLp*(
    self: MixPhysicalConnection, msg: openArray[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise newException(LPStreamError, "writeLp not implemented for MixPhysicalConnection")

method writeLp*(
    self: MixPhysicalConnection, msg: string
): Future[void] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise newException(LPStreamError, "writeLp not implemented for MixPhysicalConnection")

method shortLog*(self: MixPhysicalConnection): string {.raises: [].} =
  "[MixnetConnectionAdapter] " & self.connection.shortLog()

method initStream*(self: MixPhysicalConnection) =
  self.connection.initStream()

method closeImpl*(self: MixPhysicalConnection): Future[void] {.async: (raises: []).} =
  self.connection.closeImpl()

func hash*(self: MixPhysicalConnection): Hash =
  self.connection.hash()

proc new*(
    T: typedesc[MixPhysicalConnection], processedMessage: seq[byte]): MixPhysicalConnection =
  let instance = T(
    processedMessage: processedMessage
  )

  when defined(libp2p_agents_metrics):
    instance.shortAgent = connection.shortAgent

  instance

when defined(libp2p_agents_metrics):
  proc setShortAgent*(self: MixPhysicalConnection, shortAgent: string) =
    discard
