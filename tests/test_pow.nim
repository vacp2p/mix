import os, unittest, ../src/crypto, ../src/pow
import std/random, std/times

# Helper function to generates a 32-byte array with the specified number of leading zero bits.
proc createDummyHash(leadingBits: int): array[32, byte] =
  var result: array[32, byte]

  # Initialize the array with zeros
  for i in 0..31:
    result[i] = 0

  var bitsToSet = leadingBits
  var byteIndex = 0

  # Set bits in the array
  while bitsToSet >= 8 and byteIndex < 32:
    result[byteIndex] = 0 # Set full byte to zero
    bitsToSet -= 8
    byteIndex += 1

  # If there are remaining bits to set, set them in the next byte
  if bitsToSet > 0 and byteIndex < 32:
    let mask = (1 shl (8 - bitsToSet)) - 1
    result[byteIndex] = mask.byte

  return result

suite "pow_tests":

  test "int_to_bytes_conversion":
    assert intToBytes(255, 1) == @[255.byte], "Failed to convert int64 to 1 byte"
    assert intToBytes(65535, 2) == @[255.byte, 255.byte], "Failed to convert int64 to 2 bytes"
    assert intToBytes(65536, 4) == @[0.byte, 0.byte, 1.byte, 0.byte], "Failed to convert int64 to 4 bytes"

    # Test edge case with maximum int64 value
    let maxInt64 = int64.high
    assert intToBytes(maxInt64, 8) == @[0xFF.byte, 0xFF.byte, 0xFF.byte,
        0xFF.byte, 0xFF.byte, 0xFF.byte, 0xFF.byte, 0x7F.byte], "Failed to convert max int64 value to 8 bytes"

  test "valid_hash_check":
    let hashWithDifficultyLevel = createDummyHash(difficultyLevel)
    assert isValidHash(hashWithDifficultyLevel), "Hash with " &
        $difficultyLevel & " leading zeros must be valid"

    let hashWithLessDifficultyLevel = createDummyHash(difficultyLevel - 1)
    assert not isValidHash(hashWithLessDifficultyLevel), "Hash with " & $(
        difficultyLevel - 1) & " leading zeros should not be valid"

  test "pow_computation_verification":
    let message: seq[byte] = cast[seq[byte]]("test message")
    let result = attachPow(message)

    # Ensure result length is correct
    assert result.len == message.len + 8 + 4, "Result length should be message length + timestamp (8 bytes) + nonce (4 bytes)"

    # Simulate a delay to test timestamp validity
    sleep(1000)

    # Ensure computed PoW verifies
    assert verifyPow(result), "Valid PoWs must be verfiable"

  test "timestamp_outside_window":
    let oldTimestamp = getTime().toUnix - (6 * 60 * 60) # 6 hours ago
    let message: seq[byte] = cast[seq[byte]]("test message")
    var invalidData = attachPow(message)

    # Replace the timestamp in invalidData with an old timestamp
    for i in 0..<8:
      invalidData[message.len + i] = byte((oldTimestamp shr (i * 8)) and 0xFF)

    assert not verifyPow(invalidData), "verifyPow should return false for inputData with timestamp outside the valid window"

  test "invalid_nonce_check":
    let message: seq[byte] = cast[seq[byte]]("test message")
    var invalidData = attachPow(message)

    # Alter the nonce to invalidate the hash
    invalidData[message.len + 8] = 0xFF

    # Simulate a delay to test timestamp validity
    sleep(1000)

    assert not verifyPow(invalidData), "verifyPow should return false for inputData with invalid hash"
