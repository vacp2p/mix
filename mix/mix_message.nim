import chronicles, results
import stew/[byteutils, leb128]
import libp2p/protobuf/minprotobuf

type MixMessage* = object
  message*: seq[byte]
  codec*: string

proc init*(T: typedesc[MixMessage], message: openArray[byte], codec: string): T =
  return T(message: @message, codec: codec)

proc serialize*(mixMsg: MixMessage): Result[seq[byte], string] =
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
