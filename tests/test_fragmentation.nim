import chronicles, results, unittest
import libp2p/peerid
import ../src/[mixproto_config, fragmentation]

suite "Fragmentation":
  let peerId =
    PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()

  test "serialize_deserialize_message_chunk":
    let
      message = newSeq[byte](dataSize)
      chunks = padAndChunkMessage(message, peerId)
      (paddingLength, data, seqNo) = getMessageChunk(chunks[0])

    let serializedRes = serializeMessageChunk(chunks[0])
    if serializedRes.isErr:
      error "Serialization error", err = serializedRes.error
      fail()
    let serialized = serializedRes.get()

    let deserializedRes = deserializeMessageChunk(serialized)
    if deserializedRes.isErr:
      error "Deserialization error", err = deserializedRes.error
      fail()
    let deserialized = deserializedRes.get()

    let (dPaddingLength, dData, dSeqNo) = getMessageChunk(deserialized)

    if paddingLength != dPaddingLength:
      error "Deserialized padding length not equal to original padding length.",
        desirialized = dPaddingLength, original = paddingLength
      fail()

    if data != dData:
      error "Deserialized data not equal to original data.",
        desirialized = dData, original = data
      fail()

    if seqNo != dSeqNo:
      error "Deserialized sequence no. not equal to original sequence no.",
        desirialized = dSeqNo, original = seqNo
      fail()

  test "pad_and_unpad_small_message":
    let
      message = cast[seq[byte]]("Hello, World!")
      messageBytesLen = len(message)
      paddedMsg = padMessage(message, peerId)

    let msgRes = unpadMessage(paddedMsg)
    if msgRes.isErr:
      error "Unpad error", err = msgRes.error
      fail()
    let msg = msgRes.get()

    let (paddingLength, data, _) = getMessageChunk(paddedMsg)

    if paddingLength != uint16(dataSize - messageBytesLen):
      error "Retrieved padding length is not valid",
        pad_len = paddingLength, expected_len = uint16(dataSize - messageBytesLen)
      fail()

    if len(data) != dataSize:
      error "Retrieved padded data is not valid",
        pad_data_len = len(data), expected_len = dataSize
      fail()

    if len(msg) != messageBytesLen:
      error "Unpadded data is not valid",
        unpad_data_len = len(msg), expected_len = messageBytesLen
      fail()

  test "pad_and_chunk_large_message":
    let
      message = newSeq[byte](messageSize * 2 + 10)
      messageBytesLen = len(message)
      chunks = padAndChunkMessage(message, peerId)
      totalChunks = max(1, ceilDiv(messageBytesLen, dataSize))

    if chunks.len != totalChunks:
      error "No. of chunks does not match expected.",
        no_of_chunks = chunks.len, expected = totalChunks
      fail()

    for i in 0 ..< totalChunks:
      let (paddingLength, data, _) = getMessageChunk(chunks[i])
      if i != totalChunks - 1:
        if paddingLength != 0:
          error "Padding length must be zero."
          fail()
      else:
        let chunkSize = messageBytesLen mod dataSize

        if paddingLength != uint16(dataSize - chunkSize):
          error "Padding length is not valid",
            pad_len = paddingLength, expected_len = uint16(dataSize - chunkSize)
          fail()

      if len(data) != dataSize:
        error "Unpadded data is not valid",
          unpad_data_len = len(data), expected_len = dataSize
        fail()

  test "chunk_sequence_numbers_are_consecutive":
    let
      message = newSeq[byte](messageSize * 3)
      messageBytesLen = len(message)
      chunks = padAndChunkMessage(message, peerId)
      totalChunks = max(1, ceilDiv(messageBytesLen, dataSize))

    if chunks.len != totalChunks:
      error "No. of chunks does not match expected.",
        no_of_chunks = chunks.len, expected = totalChunks
      fail()

    let (_, _, firstSeqNo) = getMessageChunk(chunks[0])

    for i in 1 ..< totalChunks:
      let (_, _, seqNo) = getMessageChunk(chunks[i])
      if seqNo != firstSeqNo + uint32(i):
        error "Sequence number of chunks not consecutive."
        fail()

  test "chunk_data_reconstructs_original_message":
    let
      message = cast[seq[byte]]("This is a test message that will be split into multiple chunks.")
      chunks = padAndChunkMessage(message, peerId)
    var reconstructed: seq[byte]
    for chunk in chunks:
      let (paddingLength, data, _) = getMessageChunk(chunk)
      reconstructed.add(data[paddingLength.int ..^ 1])

    if reconstructed != message:
      error "The reconstructed message not same as original.",
        reconstructed = reconstructed, original = message
      fail()

  test "empty_message_handling":
    let
      message = cast[seq[byte]]("")
      chunks = padAndChunkMessage(message, peerId)
    if chunks.len != 1:
      error "Chunk length must be 1."
      fail()
    let (paddingLength, _, _) = getMessageChunk(chunks[0])
    if paddingLength != uint16(dataSize):
      error "Padding length is not valid",
        pad_len = paddingLength, expected_len = uint16(dataSize)
      fail()

  test "message_size_equal_to_chunk_size":
    let
      message = newSeq[byte](dataSize)
      chunks = padAndChunkMessage(message, peerId)
    if chunks.len != 1:
      error "Chunk length must be 1."
      fail()
    let (paddingLength, _, _) = getMessageChunk(chunks[0])
    if paddingLength != 0:
      error "Padding length must be zero."
      fail()
