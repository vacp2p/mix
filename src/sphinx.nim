import config, crypto, curve25519, pow, serialization
import nimcrypto, std/math, sequtils 

# const lambda* = 500 # Parameter for exp distribution for generating random delay

# Function to compute alphas, shared secrets, and blinders
proc computeAlpha(publicKeys: openArray[FieldElement]): tuple[alpha_0: seq[byte], s: seq[seq[byte]], errorMsg: string] =
    if publicKeys.len == 0:
        return (@[], @[@[]], "No public keys provided")

    var s: seq[seq[byte]] = newSeq[seq[byte]](publicKeys.len)
    var alpha_0: seq[byte] 
    var alpha: FieldElement
    var secret: FieldElement
    var blinders: seq[FieldElement] = @[]

    let x = generateRandomFieldElement()

    for i in 0..<publicKeys.len:
        if publicKeys[i].len != FieldElementSize:
            return (@[], @[@[]], "Invalid public key " & $i)

        # Compute alpha, shared secret, and blinder
        if i == 0:
            alpha = multiplyBasePointWithScalars([x])
            secret = multiplyPointWithScalars(publicKeys[0], [x])
            alpha_0 = fieldElementToBytes(alpha)
        else:
            alpha = multiplyPointWithScalars(alpha, [blinders[i - 1]])
            secret = multiplyPointWithScalars(publicKeys[i], blinders) # ToDo: Optimize point multiplication by multiplying scalars first

        blinders.add(bytesToFieldElement(sha256_hash(fieldElementToBytes(alpha) & fieldElementToBytes(secret))))

        s[i] = fieldElementToBytes(secret)

    return (alpha_0, s, "")

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

#[
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
]#

# Function to compute betas, gammas, and deltas  
proc computeBetaGammaDelta(s: seq[seq[byte]], hop: openArray[Hop], msg: Message, delay: seq[byte]): tuple[beta, gamma, delta: seq[byte]] = 
    let sLen = s.len
    var beta: seq[byte]
    var gamma: seq[byte]
    var delta: seq[byte]

    # Compute filler strings
    let filler = computeFillerStrings(s)

    for i in countdown(sLen-1, 0):
        # Derive AES keys, MAC key, and IVs
        let beta_aes_key = kdf(deriveKeyMaterial("beta_aes_key", s[i]))
        let mac_key = kdf(deriveKeyMaterial("mac_key", s[i]))
        let beta_iv = kdf(deriveKeyMaterial("beta_iv", s[i]))

        let delta_aes_key = kdf(deriveKeyMaterial("delta_aes_key", s[i]))
        let delta_iv = kdf(deriveKeyMaterial("delta_iv", s[i]))

        # Compute Beta and Gamma
        if i == sLen - 1:
            var paddingLength: int
            var zeroPadding: seq[byte]

            paddingLength = ((2 * (r - sLen)) + t + 2) * k
            zeroPadding = newSeq[byte](paddingLength)
            beta = aes_ctr(beta_aes_key, beta_iv, zeroPadding) & filler

            delta = aes_ctr(delta_aes_key, delta_iv, serializeMessage(msg)) 
        else:
            let routingInfo = initRoutingInfo(hop[i+1], delay, gamma, beta[0..(((2 * r) - 1) * k) - 1])
            beta = aes_ctr(beta_aes_key, beta_iv, serializeRoutingInfo(routingInfo))

            delta = aes_ctr(delta_aes_key, delta_iv, delta)

        gamma = toseq(hmac(mac_key, beta))

    return (beta, gamma, delta)

proc wrapInSphinxPacket*(message: seq[byte], publicKeys: openArray[FieldElement], delay: seq[byte], hop: openArray[Hop], msg: Message): seq[byte] =

    # Compute alphas and shared secrets
    let (alpha_0, s, errMsg) = computeAlpha(publicKeys)
    if errMsg.len > 0:
        echo "Error in createSphinxHeader: ", errMsg
        return @[]

    # Compute betas, gammas, and deltas
    let (beta_0, gamma_0, delta_0) = computeBetaGammaDelta(s, hop, msg, delay)
    
    # Serialize sphinx packet
    let sphinxPacket = initSphinxPacket(initHeader(alpha_0, beta_0, gamma_0), delta_0)
    return serializeSphinxPacket(sphinxPacket)

proc processSphinxPacket*(dSphinxPacket: seq[byte], privateKey: FieldElement): SphinxPacket =
    # Deserialize the Sphinx packet
    let sphinxPacket = deserializeSphinxPacket(dSphinxPacket)
    let (header, payload) = getSphinxPacket(sphinxPacket)
    let (alpha, beta, gamma) = getHeader(header)

    # Compute shared secret
    let s = multiplyBasePointWithScalars([privateKey])

