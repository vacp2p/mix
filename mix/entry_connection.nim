import hashes, chronos, stew/byteutils, results, chronicles
import libp2p/stream/connection
import ./mix_protocol
from fragmentation import dataSize

type
  DestinationType* = enum
    MixNode
    ForwardAddr

  Destination* = object
    peerId*: PeerId
    case kind*: DestinationType
    of ForwardAddr:
      address*: MultiAddress
    else:
      discard

proc mixNode*(T: typedesc[Destination], p: PeerId): T =
  T(kind: DestinationType.MixNode, peerId: p)

proc forwardToAddr*(T: typedesc[Destination], p: PeerId, address: MultiAddress): T =
  T(kind: DestinationType.ForwardAddr, peerId: p, address: address)

proc `$`*(d: Destination): string =
  case d.kind
  of MixNode:
    "Destination[MixNode](" & $d.peerId & ")"
  of ForwardAddr:
    "Destination[ForwardAddr](" & $d.address & "/p2p/" & $d.peerId & ")"

type MixDialer* = proc(
  msg: seq[byte], codec: string, destination: Destination
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).}

type MixEntryConnection* = ref object of Connection
  destination: Destination
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
  self.mixDialer(msg, self.codec, self.destination)

proc write*(
    self: MixEntryConnection, msg: string
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.write(msg.toBytes())

method writeLp*(
    self: MixEntryConnection, msg: openArray[byte]
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

  self.mixDialer(@buf, self.codec, self.destination)

method writeLp*(
    self: MixEntryConnection, msg: string
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.writeLp(msg.toOpenArrayByte(0, msg.high))

proc shortLog*(self: MixEntryConnection): string {.raises: [].} =
  "[MixEntryConnection] Destination: " & $self.destination

method initStream*(self: MixEntryConnection) =
  discard

method closeImpl*(
    self: MixEntryConnection
): Future[void] {.async: (raises: [], raw: true).} =
  let fut = newFuture[void]()
  fut.complete()
  return fut

func hash*(self: MixEntryConnection): Hash =
  hash($self.destination)

when defined(libp2p_agents_metrics):
  proc setShortAgent*(self: MixEntryConnection, shortAgent: string) =
    discard

proc new*(
    T: typedesc[MixEntryConnection],
    srcMix: MixProtocol,
    destination: Destination,
    codec: string,
    mixDialer: MixDialer,
): T =
  let instance = T(destination: destination, codec: codec, mixDialer: mixDialer)

  when defined(libp2p_agents_metrics):
    instance.shortAgent = connection.shortAgent

  instance

proc new*(
    T: typedesc[MixEntryConnection],
    srcMix: MixProtocol,
    destination: Destination,
    codec: string,
): T {.raises: [].} =
  var sendDialerFunc = proc(
      msg: seq[byte], codec: string, dest: Destination
  ): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
    try:
      let (peerId, destination) =
        if dest.kind == DestinationType.MixNode:
          (Opt.some(dest.peerId), Opt.none(MixDestination))
        else:
          (Opt.none(PeerId), Opt.some(MixDestination.init(dest.peerId, dest.address)))

      await srcMix.anonymizeLocalProtocolSend(msg, codec, peerId, destination)
    except CatchableError as e:
      error "Error during execution of anonymizeLocalProtocolSend: ", err = e.msg
    return

  T.new(srcMix, destination, codec, sendDialerFunc)

proc toConnection*(
    srcMix: MixProtocol, destination: Destination | PeerId, codec: string
): Connection {.gcsafe, raises: [].} =
  let dest =
    when destination is PeerId:
      Destination.mixNode(destination)
    else:
      destination
  MixEntryConnection.new(srcMix, dest, codec)
