import ./[config, seqno_generator, utils]
import results, libp2p/peerid

const paddingLengthSize* = 2
const seqNoSize* = 4
const dataSize* = MSG_SIZE - paddingLengthSize - seqNoSize

type MessageChunk* = object
  paddingLength: uint16
  data: seq[byte]
  seqNo: uint32

proc initMessageChunk*(
    paddingLength: uint16, data: seq[byte], seqNo: uint32
): MessageChunk =
  MessageChunk(paddingLength: paddingLength, data: data, seqNo: seqNo)

proc getMessageChunk*(msgChunk: MessageChunk): (uint16, seq[byte], uint32) =
  (msgChunk.paddingLength, msgChunk.data, msgChunk.seqNo)

proc serializeMessageChunk*(msgChunk: MessageChunk): Result[seq[byte], string] =
  let
    paddingBytes = uint16ToBytes(msgChunk.paddingLength)
    seqNoBytes = uint32ToBytes(msgChunk.seqNo)
  if len(msgChunk.data) != dataSize:
    return err("Padded data must be exactly " & $dataSize & " bytes")
  return ok(paddingBytes & msgChunk.data & seqNoBytes)

proc deserializeMessageChunk*(data: openArray[byte]): Result[MessageChunk, string] =
  if len(data) != MSG_SIZE:
    return err("Data must be exactly " & $MSG_SIZE & " bytes")

  let paddingLength = bytesToUInt16(data[0 .. paddingLengthSize - 1]).valueOr:
    return err("Error in byte to padding length conversion: " & error)

  let chunk = data[paddingLengthSize .. (paddingLengthSize + dataSize - 1)]

  let seqNo = bytesToUInt32(data[paddingLengthSize + dataSize ..^ 1]).valueOr:
    return err("Error in bytes to sequence no. conversion: " & error)
  ok(MessageChunk(paddingLength: paddingLength, data: @chunk, seqNo: seqNo))

proc ceilDiv*(a, b: int): int =
  (a + b - 1) div b

# Function for padding messages smaller than dataSize
proc padMessage*(messageBytes: seq[byte], peerId: PeerId): MessageChunk =
  var seqNoGen = initSeqNo(peerId)
  seqNoGen.generateSeqNo(messageBytes)

  let paddingLength = uint16(dataSize - len(messageBytes))

  let paddedData =
    if paddingLength > 0:
      let paddingBytes = newSeq[byte](paddingLength)
      paddingBytes & messageBytes
    else:
      messageBytes

  MessageChunk(
    paddingLength: paddingLength, data: paddedData, seqNo: seqNoGen.getSeqNo()
  )

proc unpadMessage*(msgChunk: MessageChunk): Result[seq[byte], string] =
  let msgLength = len(msgChunk.data) - int(msgChunk.paddingLength)
  if msgLength < 0:
    return err("Invalid padding length")

  ok(msgChunk.data[msgChunk.paddingLength ..^ 1])

proc padAndChunkMessage*(messageBytes: seq[byte], peerId: PeerId): seq[MessageChunk] =
  var seqNoGen = initSeqNo(peerId)
  seqNoGen.generateSeqNo(messageBytes)

  var chunks: seq[MessageChunk] = @[]

  # Split to chunks
  let totalChunks = max(1, ceilDiv(len(messageBytes), dataSize))
    # Ensure at least one chunk is generated
  for i in 0 ..< totalChunks:
    let
      startIdx = i * dataSize
      endIdx = min(startIdx + dataSize, len(messageBytes))
      chunkData = messageBytes[startIdx .. endIdx - 1]
      paddingLength = uint16(dataSize - len(chunkData))

    let paddedData =
      if paddingLength > 0:
        let paddingBytes = newSeq[byte](paddingLength)
        paddingBytes & chunkData
      else:
        chunkData

    let msgChunk = initMessageChunk(paddingLength, paddedData, seqNoGen.getSeqNo())
    chunks.add(msgChunk)

    seqNoGen.incSeqNo()

  return chunks

# ToDo: Unpadding and reassembling messages will be handled by the top-level applications.
# Although padding and splitting messages could also be managed at that level, we implement it here to clarify the sender's logic.
# This is crucial as the sender is responsible for wrapping messages in Sphinx packets.
