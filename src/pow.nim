import crypto, std/times

const difficultyLevel = 18 # Difficulty level

# Helper function to convert integer to sequence of bytes
proc intToBytes*(value: int64, byteSize: int): seq[byte] =
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
