import hashes, chronos, libp2p/varint
import libp2p/stream/connection

type MixExitConnection* = ref object of Connection
  message: seq[byte]

method join*(
    self: MixExitConnection
): Future[void] {.async: (raises: [CancelledError], raw: true), public.} =
  discard

method readExactly*(
    self: MixExitConnection, pbytes: pointer, nbytes: int
): Future[void] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  if nbytes == 0:
    return

  if self.message.len < nbytes:
    raise newException(
      LPStreamError, "Not enough data in to read exactly " & $nbytes & " bytes."
    )

  var pbuffer = cast[ptr UncheckedArray[byte]](pbytes)
  for i in 0 ..< nbytes:
    pbuffer[i] = self.message[i]

  if nbytes < self.message.len:
    self.message = self.message[nbytes .. ^1]
  else:
    self.isEof = true
    self.message = @[]

# ToDo: Check readLine, readVarint implementations
method readLine*(
    self: MixExitConnection, limit = 0, sep = "\r\n"
): Future[string] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  var
    lim = if limit <= 0: -1 else: limit
    result: seq[byte] = @[]
    state = 0

  while true:
    if state < len(sep):
      if self.message.len == 0:
        raise newException(LPStreamError, "Not enough data to read line.")

      let ch = self.message[0]
      self.message.delete(0)

      if byte(sep[state]) == ch:
        inc(state)
        if state == len(sep):
          break
      else:
        result.add(ch)
        state = 0

      if lim > 0 and len(result) == lim:
        break
    else:
      break

  return cast[string](result)

method readVarint*(
    self: MixExitConnection
): Future[uint64] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  var
    buffer: array[10, byte]
    bytesRead = 0

  while bytesRead < buffer.len:
    if self.message.len == 0:
      raise newException(LPStreamError, "Not enough data to read varint")

    buffer[bytesRead] = self.message[0]
    self.message.delete(0)
    bytesRead += 1

    var
      varint: uint64
      length: int
    let res = PB.getUVarint(buffer.toOpenArray(0, bytesRead - 1), length, varint)
    if res.isOk():
      return varint
    if res.error() != VarintError.Incomplete:
      break

  raise newException(LPStreamError, "Cannot parse varint")

method readLp*(
    self: MixExitConnection, maxSize: int
): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  let
    length = await self.readVarint()
    maxLen = uint64(if maxSize < 0: int.high else: maxSize)

  if length > maxLen:
    raise (ref MaxSizeError)(msg: "Message exceeds maximum length")

  if length == 0:
    self.isEof = true
    return @[]

  if self.message.len < int(length):
    raise newException(LPStreamError, "Not enough data to read " & $length & " bytes.")

  result = self.message[0 ..< int(length)]
  if int(length) == self.message.len:
    self.isEof = true
    self.message = @[]
  else:
    self.message = self.message[int(length) .. ^1]
  return result

method writeLp*(
    self: MixExitConnection, msg: openArray[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise newException(LPStreamError, "writeLp not implemented for MixExitConnection")

method writeLp*(
    self: MixExitConnection, msg: string
): Future[void] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  raise newException(LPStreamError, "writeLp not implemented for MixExitConnection")

method shortLog*(self: MixExitConnection): string {.raises: [].} =
  discard

method initStream*(self: MixExitConnection) =
  discard

method closeImpl*(
    self: MixExitConnection
): Future[void] {.async: (raises: [], raw: true).} =
  let fut = newFuture[void]()
  fut.complete()
  return fut

func hash*(self: MixExitConnection): Hash =
  discard

proc new*(T: typedesc[MixExitConnection], message: seq[byte]): MixExitConnection =
  let instance = T(message: message)

  when defined(libp2p_agents_metrics):
    instance.shortAgent = connection.shortAgent

  instance

when defined(libp2p_agents_metrics):
  proc setShortAgent*(self: MixExitConnection, shortAgent: string) =
    discard
