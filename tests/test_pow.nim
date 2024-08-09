import unittest, crypto, pow
import std/random

# Helper function to create a dummy hash with leading zeros
proc createDummyHash(leadingZeros: int): array[32, byte] =
    assert leadingZeros >= 0 and leadingZeros <= 256, "Number of leading zero bits must be between 0 and 256"
    
    var arr: array[32, byte]
    for i in 0..<32:
        arr[i] = byte(rand(256))
    
    let byteIndex = leadingZeros div 8
    let bitOffset = leadingZeros mod 8
    
    if leadingZeros > 0:
        for i in 0..<byteIndex:
            arr[i] = 0x00
    
    if byteIndex < 32:
        let mask = byte(0xFF shl (8 - bitOffset))
        arr[byteIndex] = arr[byteIndex] and mask
        
    echo "Generated Hash: ", arr
    result = arr

suite "PoW Tests":

    test "intToBytes basic conversions":
        assert intToBytes(255, 1) == @[255.byte], "Failed to convert int64 to 1 byte"
        assert intToBytes(65535, 2) == @[255.byte, 255.byte], "Failed to convert int64 to 2 bytes"
        assert intToBytes(65536, 4) == @[0.byte, 0.byte, 1.byte, 0.byte], "Failed to convert int64 to 4 bytes"

        # Test edge case with maximum int64 value
        let maxInt64 = (int64(1) shl 63) - 1  # Maximum value for int64
        assert intToBytes(maxInt64, 8) == @[0xFF.byte, 0xFF.byte, 0xFF.byte, 0xFF.byte, 0xFF.byte, 0xFF.byte, 0xFF.byte, 0x7F.byte], "Failed to convert max int64 value to 8 bytes"

    test "valid hash detection":
        let hashWith18Zeros = createDummyHash(18)
        assert isValidHash(hashWith18Zeros), "Hash with 18 leading zeros must be valid"
        
        let hashWith17Zeros = createDummyHash(17)
        assert not isValidHash(hashWith17Zeros), "Hash with 17 leading zeros should not be valid"

    test "PoW computation":
        let message: seq[byte] = cast[seq[byte]]("test message")
        let result = attachPow(message)
        
        # Ensure result length is correct
        assert result.len == message.len + 8 + 4, "Result length should be message length + timestamp (8 bytes) + nonce (4 bytes)"
        
        # Extract timestamp and nonce from result
        let timestamp = result[message.len..message.len+7]
        let nonce = result[message.len+8..message.len+11]
        
        # Ensure nonce and timestamp are correct
        let inputData = message & timestamp & nonce
        let hash = sha256_hash(inputData)
        assert isValidHash(hash), "Hash of the result does not meet the difficulty level"
