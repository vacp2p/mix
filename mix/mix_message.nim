import chronicles, results
import ./[config, utils]
import stew/[byteutils, leb128]
import libp2p/protobuf/minprotobuf

type MixMessage* = object
  message*: seq[byte]
  codec*: string

proc new*(T: typedesc[MixMessage], message: openArray[byte], codec: string): T =
  return T(message: @message, codec: codec)

proc serialize*(mixMsg: MixMessage): Result[seq[byte], string] =
  if mixMsg.codec.len == 0:
    return err("serialization failed: codec cannot be empty")

  let vbytes = toBytes(mixMsg.codec.len.uint64, Leb128)
  if vbytes.len > 2:
    return err("serialization failed: codec length exceeds 2 bytes")

  var buf =
    newSeqUninitialized[byte](vbytes.len + mixMsg.codec.len + mixMsg.message.len)
  buf[0 ..< vbytes.len] = vbytes.toOpenArray()
  buf[vbytes.len ..< mixMsg.codec.len] = mixMsg.codec.toBytes()
  buf[vbytes.len + mixMsg.codec.len ..< buf.len] = mixMsg.message
  ok(buf)

proc deserialize*(
    T: typedesc[MixMessage], data: openArray[byte]
): Result[MixMessage, string] =
  if data.len == 0:
    return err("deserialization failed: data is empty")

  var codecLen: int
  var varintLen: int
  for i in 0 ..< min(data.len, 2):
    let parsed = uint16.fromBytes(data[0 ..< i], Leb128)
    if parsed.len < 0 or (i == 1 and parsed.len == 0):
      return err("deserialization failed: invalid codec length")

    varintLen = parsed.len
    codecLen = parsed.val.int

  if data.len < varintLen + codecLen:
    return err("deserialization failed: not enough data")

  ok(
    T(
      codec: string.fromBytes(data[varintLen ..< varintLen + codecLen]),
      message: data[varintLen + codecLen ..< data.len],
    )
  )

# TODO: These are not used anywhere
# TODO: consider changing the `dest` parameter to a multiaddress
proc serializeWithDestination*(
    mixMsg: MixMessage, dest: string
): Result[seq[byte], string] =
  let destBytes = multiAddrToBytes(dest).valueOr:
    return err("Error in multiaddress conversion to bytes: " & error)

  if len(destBytes) != addrSize:
    error "Destination address must be exactly " & $addrSize & " bytes"
    return err("Destination address must be exactly " & $addrSize & " bytes")

  var serializedMixMsg = ?mixMsg.serialize()
  let oldLen = serializedMixMsg.len
  serializedMixMsg.setLen(oldLen + destBytes.len)
  copyMem(addr serializedMixMsg[oldLen], unsafeAddr destBytes[0], destBytes.len)

  return ok(serializedMixMsg)

# TODO: These are not used anywhere
proc deserializeWithDestination*(
    T: typedesc[MixMessage], data: openArray[byte]
): Result[(T, string), string] =
  if data.len <= addrSize:
    return err("Deserialization with destination failed: not enough data")

  let mixMsg = ?MixMessage.deserialize(data[0 ..^ (addrSize + 1)])

  let dest = bytesToMultiAddr(data[^addrSize ..^ 1]).valueOr:
    return err("Error in destination multiaddress conversion to bytes: " & error)

  return ok((mixMsg, dest))
