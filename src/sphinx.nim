import crypto, curve25519, sphinx_pb
import nimcrypto, std/math, sequtils

const k = 16 # Security parameter
const r = 5 # Maximum path length
const t = 3 # t.k - combined length of next hop address and delay
const lambda = 500 # Parameter for exp distribution for generating random delay 

# Function to compute alphas, shared secrets, and blinders
proc computeSharedSecrets(publicKeys: openArray[FieldElement]): tuple[headerInitialsArr: seq[HeaderInitials], errorMsg: string] =
    if publicKeys.len == 0:
        return (@[], "No public keys provided")

    var tuples: seq[HeaderInitials] = newSeq[HeaderInitials](publicKeys.len)
    var alpha: FieldElement
    var secret: FieldElement
    var blinders: seq[FieldElement] = @[]

    let x = generateRandomFieldElement()

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
proc computeFillerStrings(s: seq[seq[byte]]): seq[byte] =
    var filler: seq[byte] = @[]  # Start with an empty filler string
    
    for i in 1..<s.len:
        # Derive AES key and IV
        let aes_key = kdf(deriveKeyMaterial("filler_aes_key", s[i-1]))
        let iv = kdf(deriveKeyMaterial("filler_iv", s[i-1]))
        
        # Compute filler string
        let fillerLength = 2 * k
        let zeroPadding = newSeq[byte](fillerLength)
        filler = aes_ctr(aes_key, iv, filler & zeroPadding)
    return filler

# ToDo: Replace with better implementation for production
# Helper function to generate a random 16-bit delay
proc generateRandomDelay(): seq[byte] =
  # Generate 2 random bytes
  var randBytes: array[2, byte]
  discard randomBytes(randBytes)
  
  # Convert bytes to a float between 0 and 1
  let randomValue = (uint16(randBytes[0]) shl 8 or uint16(randBytes[1])).float / 65535.0
  
  # Compute the delay using capped exponential distribution
  let delay = -ln(randomValue) / lambda
  let cappedDelay = min(int(delay), 65535)

  # Convert delay to seq[byte]
  var delayBytes: array[2, byte]
  delayBytes[0] = byte(cappedDelay and 0xFF)
  delayBytes[1] = byte((cappedDelay shr 8) and 0xFF)
  return toseq(delayBytes)
  
proc computeBetasGammasDeltas(s: seq[seq[byte]], filler: seq[byte], address: openArray[string], message: seq[byte]): tuple[betas: seq[seq[byte]], gammas: seq[seq[byte]]] = 
    let sLen = s.len
    var betas: seq[seq[byte]] = newSeq[seq[byte]](sLen)
    var gammas: seq[seq[byte]] = newSeq[seq[byte]](sLen)
    var deltas: seq[seq[byte]] = newSeq[seq[byte]](sLen)

    for i in countdown(sLen-1, 0):
        # Derive AES keys, MAC key, and IVs
        let beta_aes_key = kdf(deriveKeyMaterial("beta_aes_key", s[i]))
        let mac_key = kdf(deriveKeyMaterial("mac_key", s[i]))
        let beta_iv = kdf(deriveKeyMaterial("beta_iv", s[i]))

        let delta_aes_key = kdf(deriveKeyMaterial("delta_aes_key", s[i]))
        let delta_iv = kdf(deriveKeyMaterial("delta_iv", s[i]))

        # Generate Random Delay
        var delayBytes = generateRandomDelay()

        # Compute Beta and Gamma
        if i == sLen - 1:
            var fillerLength: int
            var zeroPadding: seq[byte]

            fillerLength = ((2 * (r - sLen)) + t + 2) * k
            zeroPadding = newSeq[byte](fillerLength)
            betas.add(aes_ctr(beta_aes_key, beta_iv, zeroPadding) & filler)

            fillerLength = k
            zeroPadding = newSeq[byte](fillerLength)
            deltas.add(aes_ctr(delta_aes_key, delta_iv, zeroPadding & message)) 
        else:
            let addrBytes = @(address[i+1].toOpenArrayByte(0, address[i+1].high))
            betas.add(aes_ctr(beta_aes_key, beta_iv, addrBytes & delayBytes & gammas[i+1] & betas[i+1][0..(((2 * r) - 1) * k) - 1]))

            deltas.add(aes_ctr(delta_aes_key, delta_iv, deltas[i+1]))

        gammas.add(toseq(hmac(mac_key, betas[i])))

    return (betas, gammas)

proc wrapInSphinxPacket*(message: seq[byte], publicKeys: openArray[FieldElement]): SphinxPacket =
    # Create HeaderInitials, Header, and handle any errors
    let (headerInitials, errMsg) = computeSharedSecrets(publicKeys)
    if errMsg.len > 0:
        echo "Error in createSphinxHeader: ", errMsg
        return SphinxPacket()
    return SphinxPacket()