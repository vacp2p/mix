import os, unittest, ../src/crypto, ../src/pow
import chronicles, results, std/random, std/times

# Helper function to generates a 32-byte array with the specified number of leading zero bits.
proc createDummyHash(leadingBits: int): array[32, byte] =
  var res: array[32, byte]

  # Initialize the array with zeros
  for i in 0 .. 31:
    res[i] = 0

  var
    bitsToSet = leadingBits
    byteIndex = 0

  # Set bits in the array
  while bitsToSet >= 8 and byteIndex < 32:
    result[byteIndex] = 0 # Set full byte to zero
    bitsToSet -= 8
    byteIndex += 1

  # If there are remaining bits to set, set them in the next byte
  if bitsToSet > 0 and byteIndex < 32:
    let mask = (1 shl (8 - bitsToSet)) - 1
    res[byteIndex] = mask.byte

  return res

suite "pow_tests":
  test "int_to_bytes_conversion":
    var tmpRes: Result[seq[byte], string]
    var tmp: seq[byte]

    tmpRes = intToBytes(255, 1)
    if tmpRes.isErr:
      error "Convert to bytes error", err = tmpRes.error
    tmp = tmpRes.get()

    if tmp != @[255.byte]:
      error "Failed to convert int64 to 1 byte"
      fail()

    tmpRes = intToBytes(65535, 2)
    if tmpRes.isErr:
      error "Convert to bytes error", err = tmpRes.error
    tmp = tmpRes.get()

    if tmp != @[255.byte, 255.byte]:
      error "Failed to convert int64 to 2 bytes"
      fail()

    tmpRes = intToBytes(65536, 4)
    if tmpRes.isErr:
      error "Convert to bytes error", err = tmpRes.error
    tmp = tmpRes.get()

    if tmp != @[0.byte, 0.byte, 1.byte, 0.byte]:
      error "Failed to convert int64 to 4 bytes"
      fail()

    # Test edge case with maximum int64 value
    let maxInt64 = int64.high
    tmpRes = intToBytes(maxInt64, 8)
    if tmpRes.isErr:
      error "Convert to bytes error", err = tmpRes.error
    tmp = tmpRes.get()

    if tmp !=
        @[
          0xFF.byte, 0xFF.byte, 0xFF.byte, 0xFF.byte, 0xFF.byte, 0xFF.byte, 0xFF.byte,
          0x7F.byte,
        ]:
      error "Failed to convert int64 to 8 bytes"
      fail()

  test "valid_hash_check":
    let hashWithDifficultyLevel = createDummyHash(difficultyLevel)
    assert isValidHash(hashWithDifficultyLevel),
      "Hash with " & $difficultyLevel & " leading zeros must be valid"

    let hashWithLessDifficultyLevel = createDummyHash(difficultyLevel - 1)
    assert not isValidHash(hashWithLessDifficultyLevel),
      "Hash with " & $(difficultyLevel - 1) & " leading zeros should not be valid"

  test "pow_computation_verification":
    let message: seq[byte] = cast[seq[byte]]("test message")

    let powRes = attachPow(message)
    if powRes.isErr:
      error "Error in PoW generation", err = powRes.error
      fail()
    let pow = powRes.get()

    # Ensure result length is correct
    if pow.len != message.len + 8 + 4:
      error "Incorrect message length",
        msglen = $pow.len, expected = $(message.len + 8 + 4)
      fail()

    # Simulate a delay to test timestamp validity
    sleep(1000)

    # Ensure computed PoW verifies
    let verRes = verifyPow(pow)
    if verRes.isErr:
      error "PoW verification error", err = verRes
      fail()
    let ver = verRes.get()

    if not ver:
      error "Valid PoWs must be verfiable"
      fail()

  test "timestamp_outside_window":
    let
      oldTimestamp = getTime().toUnix - (6 * 60 * 60) # 6 hours ago
      message: seq[byte] = cast[seq[byte]]("test message")

    let invalidDataRes = attachPow(message)
    if invalidDataRes.isErr:
      error "Error in PoW generation", err = invalidDataRes.error
      fail()
    var invalidData = invalidDataRes.get()

    # Replace the timestamp in invalidData with an old timestamp
    for i in 0 ..< 8:
      invalidData[message.len + i] = byte((oldTimestamp shr (i * 8)) and 0xFF)

    let verRes = verifyPow(invalidData)
    if verRes.isErr:
      error "PoW verification error", err = verRes
      fail()
    let ver = verRes.get()

    if ver:
      error "verifyPow should return false for inputData with timestamp outside the valid window"
      fail()

  test "invalid_nonce_check":
    let message: seq[byte] = cast[seq[byte]]("test message")

    let invalidDataRes = attachPow(message)
    if invalidDataRes.isErr:
      error "Error in PoW generation", err = invalidDataRes.error
      fail()
    var invalidData = invalidDataRes.get()

    # Alter the nonce to invalidate the hash
    invalidData[message.len + 8] = 0xFF

    # Simulate a delay to test timestamp validity
    sleep(1000)

    let verRes = verifyPow(invalidData)
    if verRes.isErr:
      error "PoW verification error", err = verRes
      fail()
    let ver = verRes.get()

    if ver:
      error "verifyPow should return false for inputData with invalid hash"
      fail()
