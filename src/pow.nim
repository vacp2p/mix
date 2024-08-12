import crypto, std/times

const 
    difficultyLevel* = 18 # Difficulty level
    acceptanceWindow* = 5 * 60 # Acceptance time window in seconds
    nonceSize = 4 # Nonce size
    timestampSize = 8 # Timestamp size

# Helper function to convert integer to sequence of bytes
proc intToBytes*(value: int64, byteSize: int): seq[byte] =
    # Ensure byteSize is within the acceptable range
    assert byteSize >= 1 and byteSize <= 8, "Byte size must be between 1 and 8 inclusive"

    # Calculate the maximum value that can be represented with byteSize bytes
    let maxValue = if byteSize == 8:
        int64.high
    else:
        (1 shl (byteSize * 8)) - 1

    assert value >= 0 and value <= maxValue, "Value too large for the specified byte size"
    
    result = newSeq[byte](byteSize)
    for i in 0..<byteSize:
        result[i] = byte((value shr (i * 8)) and 0xFF)

# Function to check if the computed hash meets the difficulty level
proc isValidHash*(hash: array[32, byte]): bool =
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
proc attachPow*(message: seq[byte]): seq[byte] =
    var nonce = 0
    var hash: array[32, byte]
    let timestamp = intToBytes(getTime().toUnix, 8)

    while true:
        let nonceBytes = intToBytes(nonce, 4)
        let inputData = message & timestamp & nonceBytes
        hash = sha256_hash(inputData)

        # Check if hash meets the difficulty level
        if isValidHash(hash):
            return inputData

        nonce.inc()  # Increment nonce if hash does not meet criteria

# Function to verify the Proof of Work (PoW)
proc verifyPow*(inputData: openArray[byte]): bool =
    # Ensure inputData is at least as long as timestamp + nonceBytes
    assert inputData.len >= (timestampSize + nonceSize), "Input data must be at least as long as the timestamp + nonce size"

    # Extract timestamp from inputData
    let extractedTimestamp = inputData[^(nonceSize + timestampSize)..^nonceSize]

    # Check if the extracted timestamp is within the acceptable time window
    let currentTime = getTime().toUnix
    var timestamp: int64 = 0
    for i in 0..<8:
        timestamp = timestamp or (int64(extractedTimestamp[i]) shl (i * 8))
    let timeWindow = currentTime - timestamp
    if timeWindow < 0 or timeWindow > acceptanceWindow:
        return false

    # Recompute hash and verify it
    let hash = sha256_hash(inputData)
    return isValidHash(hash)