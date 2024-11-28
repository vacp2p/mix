import hashes, chronos
import libp2p/stream/connection

type MixDialer* = proc(msg: seq[byte], destination: MultiAddress): Future[void] {.
  async: (raises: [CancelledError, LPStreamError], raw: true)
.}

type MixLogicalConnection* = ref object of Connection
  destination: MultiAddress
  mixDialer: MixDialer

method join*(
    self: MixLogicalConnection
): Future[void] {.async: (raises: [CancelledError], raw: true), public.} =
  discard

method readExactly*(
    self: MixLogicalConnection, pbytes: pointer, nbytes: int
): Future[void] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise
    newException(LPStreamError, "readExactly not implemented for MixLogicalConnection")

method readLine*(
    self: MixLogicalConnection, limit = 0, sep = "\r\n"
): Future[string] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise newException(LPStreamError, "readLine not implemented for MixLogicalConnection")

method readVarint*(
    self: MixLogicalConnection
): Future[uint64] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise
    newException(LPStreamError, "readVarint not implemented for MixLogicalConnection")

method readLp*(
    self: MixLogicalConnection, maxSize: int
): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise newException(LPStreamError, "readLp not implemented for MixLogicalConnection")

method writeLp*(
    self: MixLogicalConnection, msg: openArray[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.mixDialer(@msg, self.destination)

method writeLp*(
    self: MixLogicalConnection, msg: string
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.writeLp(msg.toOpenArrayByte(0, msg.high))

method shortLog*(self: MixLogicalConnection): string {.raises: [].} =
  "[MixLogicalConnection] Destination: " & $self.destination

method initStream*(self: MixLogicalConnection) =
  discard

method closeImpl*(self: MixLogicalConnection): Future[void] {.async: (raises: []).} =
  discard

func hash*(self: MixLogicalConnection): Hash =
  hash(self.destination)

proc new*(
    T: typedesc[MixLogicalConnection], destination: MultiAddress, sendFunc: MixDialer
): MixLogicalConnection =
  let instance = T(destination: destination, mixDialer: sendFunc)

  when defined(libp2p_agents_metrics):
    instance.shortAgent = connection.shortAgent

  instance

when defined(libp2p_agents_metrics):
  proc setShortAgent*(self: MixLogicalConnection, shortAgent: string) =
    discard
