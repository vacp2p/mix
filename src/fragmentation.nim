import config, seqno_generator, utils
import libp2p/peerid

const paddingLengthSize* = 2
const seqNoSize* = 4
const dataSize* = messageSize - paddingLengthSize - seqNoSize

type MessageChunk* = object
  paddingLength: uint16
  data: seq[byte]
  seqNo: uint32

proc initMessageChunk*(
    paddingLength: uint16, data: seq[byte], seqNo: uint32
): MessageChunk =
  result.paddingLength = paddingLength
  result.data = data
  result.seqNo = seqNo

proc getMessageChunk*(msgChunk: MessageChunk): (uint16, seq[byte], uint32) =
  (msgChunk.paddingLength, msgChunk.data, msgChunk.seqNo)

proc serializeMessageChunk*(msgChunk: MessageChunk): seq[byte] =
  let paddingBytes = uint16ToBytes(msgChunk.paddingLength)
  let seqNoBytes = uint32ToBytes(msgChunk.seqNo)
  assert len(msgChunk.data) == dataSize,
    "Padded data must be exactly " & $dataSize & " bytes"
  result = paddingBytes & msgChunk.data & seqNoBytes

proc deserializeMessageChunk*(data: openArray[byte]): MessageChunk =
  assert len(data) == messageSize, "Data must be exactly " & $messageSize & " bytes"

  result.paddingLength = bytesToUInt16(data[0 .. paddingLengthSize - 1])
  result.data = data[paddingLengthSize .. (paddingLengthSize + dataSize - 1)]
  result.seqNo = bytesToUInt32(data[paddingLengthSize + dataSize ..^ 1])

proc ceilDiv*(a, b: int): int =
  (a + b - 1) div b

# Function for padding messages smaller than dataSize
proc padMessage*(messageBytes: seq[byte], peerId: PeerId): MessageChunk =
  var seqNoGen = initSeqNo(peerId)
  seqNoGen.generateSeqNo(messageBytes)

  # Calculate padding length
  let paddingLength = uint16(dataSize - len(messageBytes))

  let paddedData =
    if paddingLength > 0:
      # Create padding bytes
      let paddingBytes = newSeq[byte](paddingLength)
      paddingBytes & messageBytes
    else:
      messageBytes

  result = initMessageChunk(paddingLength, paddedData, seqNoGen.getSeqNo())

proc unpadMessage*(msgChunk: MessageChunk): seq[byte] =
  let msgLength = len(msgChunk.data) - int(msgChunk.paddingLength)

  assert msgLength >= 0, "Invalid padding length"

  return msgChunk.data[msgChunk.paddingLength ..^ 1]

proc padAndChunkMessage*(messageBytes: seq[byte], peerId: PeerId): seq[MessageChunk] =
  var seqNoGen = initSeqNo(peerId)
  seqNoGen.generateSeqNo(messageBytes)

  var chunks: seq[MessageChunk] = @[]

  # Split to chunks
  let totalChunks = max(1, ceilDiv(len(messageBytes), dataSize))
    # Ensure at least one chunk is generated
  for i in 0 ..< totalChunks:
    let startIdx = i * dataSize
    let endIdx = min(startIdx + dataSize, len(messageBytes))
    let chunkData = messageBytes[startIdx .. endIdx - 1]

    # Calculate padding length
    let paddingLength = uint16(dataSize - len(chunkData))

    let paddedData =
      if paddingLength > 0:
        # Create padding bytes
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
