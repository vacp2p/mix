import std/times, results
import ../crypto

const
  difficultyLevel* = 18 # Difficulty level
  acceptanceWindow* = 5 * 60 # Acceptance time window in seconds
  nonceSize = 4 # Nonce size
  timestampSize = 8 # Timestamp size
  powSize* = nonceSize + timestampSize # PoW Size

# Helper function to convert integer to sequence of bytes
proc intToBytes*(
    value: int64, byteSize: int
): Result[seq[byte], string] {.raises: [].} =
  # Ensure byteSize is within the acceptable range
  if byteSize < 1 or byteSize > 8:
    return err("Byte size must be between 1 and 8 inclusive")

  # Calculate the maximum value that can be represented with byteSize bytes
  let maxValue =
    if byteSize == 8:
      int64.high
    else:
      (1 shl (byteSize * 8)) - 1

  if value < 0 or value > maxValue:
    return err("Value too large for the specified byte size")

  var res = newSeq[byte](byteSize)
  for i in 0 ..< byteSize:
    res[i] = byte((value shr (i * 8)) and 0xFF)

  return ok(res)

# Function to check if the computed hash meets the difficulty level
proc isValidHash*(hash: array[32, byte]): bool {.raises: [].} =
  var zeroBits = 0
  for byte in hash:
    for i in countdown(7, 0):
      if ((byte shr i) and 1) == 0:
        zeroBits += 1
        if zeroBits >= difficultyLevel:
          return true
      else:
        return false
  return false

# Function to find a valid nonce that produces a hash with at least 'difficultyLevel' leading zeros. Attaches PoW to the input.
proc attachPow*(message: seq[byte]): Result[seq[byte], string] {.raises: [].} =
  var
    nonce = 0
    hash: array[32, byte]

  let timestampRes = intToBytes(getTime().toUnix, 8)
  if timestampRes.isErr:
    return err("Timestamp conversion error: " & $timestampRes.error)
  let timestamp = timestampRes.get()

  while true:
    let nonceBytesRes = intToBytes(nonce, 4)
    if nonceBytesRes.isErr:
      return err("Nonce conversion error: " & $timestampRes.error)
    let nonceBytes = nonceBytesRes.get()

    let inputData = message & timestamp & nonceBytes
    hash = sha256_hash(inputData)

    # Check if hash meets the difficulty level
    if isValidHash(hash):
      return ok(inputData)

    nonce.inc() # Increment nonce if hash does not meet criteria

# Function to verify the Proof of Work (PoW)
proc verifyPow*(inputData: openArray[byte]): Result[bool, string] {.raises: [].} =
  # Ensure inputData is at least as long as timestamp + nonceBytes
  if inputData.len < (timestampSize + nonceSize):
    return err("Input data must be at least as long as the timestamp + nonce size")

  # Extract timestamp from inputData
  let extractedTimestamp = inputData[^(nonceSize + timestampSize) ..^ nonceSize]

  # Check if the extracted timestamp is within the acceptable time window
  let currentTime = getTime().toUnix
  var timestamp: int64 = 0
  for i in 0 ..< 8:
    timestamp = timestamp or (int64(extractedTimestamp[i]) shl (i * 8))
  let timeWindow = currentTime - timestamp
  if timeWindow < 0 or timeWindow > acceptanceWindow:
    return ok(false)

  # Recompute hash and verify it
  let hash = sha256_hash(inputData)
  return ok(isValidHash(hash))
