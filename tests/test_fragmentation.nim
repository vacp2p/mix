import unittest
import libp2p/peerid
import ../src/config, ../src/fragmentation

suite "Fragmentation":
  let peerId = PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()

  test "serialize_deserialize_message_chunk":
    let message = newSeq[byte](dataSize)
    let chunks = padAndChunkMessage(message, peerId)
    let (paddingLength, data, seqNo) = getMessageChunk(chunks[0])

    let serialized = serializeMessageChunk(chunks[0])
    let deserialized = deserializeMessageChunk(serialized)
    let (dPaddingLength, dData, dSeqNo) = getMessageChunk(deserialized)

    assert paddingLength == dPaddingLength, "Padding length not equal to original padding length."
    assert data == dData, "Data not equal to original data."
    assert seqNo == dSeqNo, "Sequence no. not equal to original sequence no."

  test "pad_and_chunk_small_message":
    let message = cast[seq[byte]]("Hello, World!") 
    let messageBytesLen = len(message)

    let paddedMsg = padMessage(message, peerId)

    let (paddingLength, data, _) = getMessageChunk(paddedMsg)
    assert paddingLength == uint16(dataSize - messageBytesLen), "Padding length must be exactly " & $(dataSize - messageBytesLen) & " bytes." 
    assert len(data) == dataSize, "Padded data must be exactly " & $dataSize & " bytes."

  test "pad_and_chunk_large_message":
    let message = newSeq[byte](messageSize * 2 + 10)
    let messageBytesLen = len(message)

    let chunks = padAndChunkMessage(message, peerId)
    let totalChunks = max(1, ceilDiv(messageBytesLen, dataSize))
    assert chunks.len == totalChunks, "Chunk length must be " & $totalChunks & "."

    for i in 0..<totalChunks:
        let (paddingLength, data, _) = getMessageChunk(chunks[i])
        if i != totalChunks - 1:
            assert paddingLength == 0, "Padding length must be zero."
        else:
            let chunkSize = messageBytesLen mod dataSize
            assert paddingLength == uint16(dataSize - chunkSize), "Padding length must be exactly " & $(dataSize - chunkSize) & " bytes."
        assert len(data) == dataSize, "Padded data must be exactly " & $dataSize & " bytes."

  test "chunk_sequence_numbers_are_consecutive":
    let message = newSeq[byte](messageSize * 3)
    let messageBytesLen = len(message)

    let chunks = padAndChunkMessage(message, peerId)
    let totalChunks = max(1, ceilDiv(messageBytesLen, dataSize))
    assert chunks.len == totalChunks, "Chunk length must be " & $totalChunks & "."

    let (_, _, firstSeqNo) = getMessageChunk(chunks[0])

    for i in 1..<totalChunks:
        let (_, _, seqNo) = getMessageChunk(chunks[i])
        assert seqNo == firstSeqNo + uint32(i), "Sequence number of chunks not consecutive."

  test "chunk_data_reconstructs_original_message":
    let message = cast[seq[byte]]("This is a test message that will be split into multiple chunks.")
    let chunks = padAndChunkMessage(message, peerId)
    var reconstructed: seq[byte]
    for chunk in chunks:
      let (paddingLength, data, _) = getMessageChunk(chunk)
      reconstructed.add(data[paddingLength.int..^1])
    assert reconstructed == message, "The reconstructed message not same as original."

  test "empty_message_handling":
    let message = cast[seq[byte]]("")
    let chunks = padAndChunkMessage(message, peerId)
    assert chunks.len == 1, "Chunk length must be 1."
    let (paddingLength, _, _) = getMessageChunk(chunks[0])
    assert paddingLength == uint16(dataSize), "Padding length must be exactly " & $(dataSize) & " bytes."

  test "message_size_equal_to_chunk_size":
    let message = newSeq[byte](dataSize)
    let chunks = padAndChunkMessage(message, peerId)
    assert chunks.len == 1, "Chunk length must be 1."
    let (paddingLength, _, _) = getMessageChunk(chunks[0])
    assert paddingLength == 0, "Padding length must be zero."
