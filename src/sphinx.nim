import crypto, curve25519, sphinx_pb
import nimcrypto, std/math

const k = 16 # Security parameter
const r = 5 # Maximum path length
const t = 3 # t.k - combined length of next hop address and delay
const lambda = 500 # Parameter for exp distribution for generating random delay 

# Function to compute alphas, shared secrets, and blinders
proc computeSharedSecrets(publicKeys: seq[FieldElement], x:FieldElement): tuple[headerInitialsSeq: seq[HeaderInitials], errorMsg: string] =
    if publicKeys.len == 0:
        return (@[], "No public keys provided")

    var tuples: seq[HeaderInitials] = newSeq[HeaderInitials](publicKeys.len)
    var alpha: FieldElement
    var secret: FieldElement
    var blinders: seq[FieldElement] = @[]

    for i in 0..<publicKeys.len:
        if publicKeys[i].len != FieldElementSize:
            return (@[], "Invalid public key " & $i)

        # Compute alpha, shared secret, and blinder
        if i == 0:
            alpha = multiplyBasePointWithScalars(@[x])
            secret = multiplyPointWithScalars(publicKeys[0], @[x])
        else:
            alpha = multiplyPointWithScalars(alpha, @[blinders[i - 1]])
            secret = multiplyPointWithScalars(publicKeys[i], blinders) # ToDo: Optimize point multiplication by multiplying scalars first

        blinders.add(bytesToFieldElement(sha256_hash(fieldElementToBytes(alpha) & fieldElementToBytes(secret))))

        tuples[i] = HeaderInitials()  
        tuples[i].Alpha = fieldElementToBytes(alpha)
        tuples[i].Secret = fieldElementToBytes(secret)
        tuples[i].Blinder = fieldElementToBytes(blinders[i])

    return (tuples, "")

# Helper function to derive key material
proc deriveKeyMaterial(keyName: string, s: seq[byte]): seq[byte] =
    let keyNameBytes = @(keyName.toOpenArrayByte(0, keyName.high))
    result = keyNameBytes & s

# Function to compute filler strings
proc computeFillerStrings(s: seq[seq[byte]]): seq[seq[byte]] =
    var fillers: seq[seq[byte]] = @[]
    fillers.add(@[])  # φ_0 is an empty string

    for i in 1..<s.len:
        # Derive AES key and IV 
        let aes_key = kdf(deriveKeyMaterial("filler_aes_key", s[i-1]))
        let iv = kdf(deriveKeyMaterial("filler_iv", s[i-1]))

        # Compute filler string
        let fillerLength = 2 * k
        let zeroPadding = newSeq[byte](fillerLength)
        fillers.add(aes_ctr(aes_key, iv, fillers[i-1] & zeroPadding))
    return fillers

# ToDo: Replace with better implementation for production
# Helper function to generate a random 16-bit delay
proc generateRandomDelay(): int =
  # Generate 2 random bytes
  var randBytes: array[2, byte]
  discard randomBytes(randBytes)
  
  # Convert bytes to a float between 0 and 1
  let randomValue = (uint16(randBytes[0]) shl 8 or uint16(randBytes[1])).float / 65535.0
  
  # Compute the delay using capped exponential distribution
  let delay = -ln(randomValue) / lambda
  result = min(int(delay), 65535)