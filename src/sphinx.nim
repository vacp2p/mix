import results, sequtils
import std/math
import config, crypto, curve25519, pow, serialization, tag_manager

# Define possible outcomes of processing a Sphinx packet
type ProcessingStatus* = enum
  Success # Packet processed successfully
  Duplicate # Packet was discarded due to duplicate tag
  InvalidMAC # Packet was discarded due to MAC verification failure
  InvalidPoW
    # Packet was discarded due to PoW verification failure

    # const lambda* = 500 # Parameter for exp distribution for generating random delay

    # Function to compute alphas, shared secrets, and blinders

proc computeAlpha(
    publicKeys: openArray[FieldElement]
): Result[(seq[byte], seq[seq[byte]]), string] =
  if publicKeys.len == 0:
    return err("No public keys provided")

  var
    s: seq[seq[byte]] = newSeq[seq[byte]](publicKeys.len)
    alpha_0: seq[byte]
    alpha: FieldElement
    secret: FieldElement
    blinders: seq[FieldElement] = @[]

  let xRes = generateRandomFieldElement()
  if xRes.isErr:
    return err("Generate field element error: " & xRes.error)
  let x = xRes.get()

  blinders.add(x)

  for i in 0 ..< publicKeys.len:
    if publicKeys[i].len != FieldElementSize:
      return err("Invalid public key " & $i)

    # Compute alpha, shared secret, and blinder
    if i == 0:
      let alphaRes = multiplyBasePointWithScalars([blinders[i]])
      if alphaRes.isErr:
        return err("Multiply base point with scalars error: " & alphaRes.error)
      alpha = alphaRes.get()

      alpha_0 = fieldElementToBytes(alpha)
    else:
      alpha = multiplyPointWithScalars(alpha, [blinders[i]])

    secret = multiplyPointWithScalars(publicKeys[i], blinders)
      # ToDo: Optimize point multiplication by multiplying scalars first

    let blinderRes = bytesToFieldElement(
      sha256_hash(fieldElementToBytes(alpha) & fieldElementToBytes(secret))
    )
    if blinderRes.isErr:
      return err("Error in bytes to field element conversion: " & blinderRes.error)
    let blinder = blinderRes.get()

    blinders.add(blinder)

    s[i] = fieldElementToBytes(secret)

  return ok((alpha_0, s))

# Helper function to derive key material
proc deriveKeyMaterial(keyName: string, s: seq[byte]): seq[byte] =
  let keyNameBytes = @(keyName.toOpenArrayByte(0, keyName.high))
  return keyNameBytes & s

# Function to compute filler strings
proc computeFillerStrings(s: seq[seq[byte]]): Result[seq[byte], string] =
  var filler: seq[byte] = @[] # Start with an empty filler string

  for i in 1 ..< s.len:
    # Derive AES key and IV
    let
      aes_key = kdf(deriveKeyMaterial("aes_key", s[i - 1]))
      iv = kdf(deriveKeyMaterial("iv", s[i - 1]))

    # Compute filler string
    let
      fillerLength = (t + 1) * k
      zeroPadding = newSeq[byte](fillerLength)

    let fillerRes = aes_ctr_start_index(
      aes_key, iv, filler & zeroPadding, (((t + 1) * (r - i)) + t + 2) * k
    )
    if fillerRes.isErr:
      return err("Error in aes with start index: " & fillerRes.error)
    filler = fillerRes.get()

  return ok(filler)

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
proc computeBetaGammaDelta(
    s: seq[seq[byte]], hop: openArray[Hop], msg: Message, delay: openArray[seq[byte]]
): Result[(seq[byte], seq[byte], seq[byte]), string] =
  let sLen = s.len
  var
    beta: seq[byte]
    gamma: seq[byte]
    delta: seq[byte]

  # Compute filler strings
  let fillerRes = computeFillerStrings(s)
  if fillerRes.isErr:
    return err("Error in filler generation: " & fillerRes.error)
  let filler = fillerRes.get()

  for i in countdown(sLen - 1, 0):
    # Derive AES keys, MAC key, and IVs
    let
      beta_aes_key = kdf(deriveKeyMaterial("aes_key", s[i]))
      mac_key = kdf(deriveKeyMaterial("mac_key", s[i]))
      beta_iv = kdf(deriveKeyMaterial("iv", s[i]))

      delta_aes_key = kdf(deriveKeyMaterial("delta_aes_key", s[i]))
      delta_iv = kdf(deriveKeyMaterial("delta_iv", s[i]))

    # Compute Beta and Gamma
    if i == sLen - 1:
      let
        paddingLength = (((t + 1) * (r - L)) + t + 2) * k
        zeroPadding = newSeq[byte](paddingLength)

      let aesRes = aes_ctr(beta_aes_key, beta_iv, zeroPadding)
      if aesRes.isErr:
        return err("Error in aes: " & aesRes.error)
      beta = aesRes.get() & filler

      let serializeRes = serializeMessage(msg)
      if serializeRes.isErr:
        return err("Message serialization error: " & serializeRes.error)

      let deltaRes = aes_ctr(delta_aes_key, delta_iv, serializeRes.get())
      if deltaRes.isErr:
        return err("Error in aes: " & deltaRes.error)
      delta = deltaRes.get()
    else:
      let routingInfo = initRoutingInfo(
        hop[i + 1], delay[i + 1], gamma, beta[0 .. (((r * (t + 1)) - t) * k) - 1]
      )

      let serializeRes = serializeRoutingInfo(routingInfo)
      if serializeRes.isErr:
        return err("Routing info serialization error: " & serializeRes.error)

      let betaRes = aes_ctr(beta_aes_key, beta_iv, serializeRes.get())
      if betaRes.isErr:
        return err("Error in aes: " & betaRes.error)
      beta = betaRes.get()

      let deltaRes = aes_ctr(delta_aes_key, delta_iv, delta)
      if deltaRes.isErr:
        return err("Error in aes: " & deltaRes.error)
      delta = deltaRes.get()

    gamma = toseq(hmac(mac_key, beta))

  return ok((beta, gamma, delta))

proc wrapInSphinxPacket*(
    msg: Message,
    publicKeys: openArray[FieldElement],
    delay: seq[seq[byte]],
    hop: openArray[Hop],
): Result[seq[byte], string] =
  # Compute PoW
  let powRes = attachPow(getMessage(msg))
  if powRes.isErr:
    return err("Proof of work generation error: " & powRes.error)
  let msgPow = initMessage(powRes.get())

  # Compute alphas and shared secrets
  let res1 = computeAlpha(publicKeys)
  if res1.isErr:
    return err("Error in alpha generation: " & res1.error)
  let (alpha_0, s) = res1.get()

  # Compute betas, gammas, and deltas
  let res2 = computeBetaGammaDelta(s, hop, msgPow, delay)
  if res2.isErr:
    return err("Error in beta, gamma, and delta generation: " & res2.error)
  let (beta_0, gamma_0, delta_0) = res2.get()

  # Serialize sphinx packet
  let sphinxPacket = initSphinxPacket(initHeader(alpha_0, beta_0, gamma_0), delta_0)

  let serializeRes = serializeSphinxPacket(sphinxPacket)
  if serializeRes.isErr:
    return err("Sphinx packet serialization error: " & serializeRes.error)

  return ok(serializeRes.get())

proc processSphinxPacket*(
    serSphinxPacket: seq[byte], privateKey: FieldElement, tm: var TagManager
): Result[(Hop, seq[byte], seq[byte], ProcessingStatus), string] =
  # Deserialize the Sphinx packet
  let deserializeRes = deserializeSphinxPacket(serSphinxPacket)
  if deserializeRes.isErr:
    return err("Sphinx packet deserialization error: " & deserializeRes.error)

  let
    (header, payload) = getSphinxPacket(deserializeRes.get())
    (alpha, beta, gamma) = getHeader(header)

  # Compute shared secret
  let alphaRes = bytesToFieldElement(alpha)
  if alphaRes.isErr:
    return err("Error in bytes to field element conversion: " & alphaRes.error)

  let
    s = multiplyPointWithScalars(alphaRes.get(), [privateKey])
    sBytes = fieldElementToBytes(s)

  # Check if the tag has been seen
  if isTagSeen(tm, s):
    return ok((Hop(), @[], @[], Duplicate))

  # Compute MAC
  let mac_key = kdf(deriveKeyMaterial("mac_key", sBytes))

  if not (toseq(hmac(mac_key, beta)) == gamma):
    # If MAC not verified
    return ok((Hop(), @[], @[], InvalidMAC))

  # Store the tag as seen
  addTag(tm, s)

  # Derive AES key and IV
  let
    beta_aes_key = kdf(deriveKeyMaterial("aes_key", sBytes))
    beta_iv = kdf(deriveKeyMaterial("iv", sBytes))

    delta_aes_key = kdf(deriveKeyMaterial("delta_aes_key", sBytes))
    delta_iv = kdf(deriveKeyMaterial("delta_iv", sBytes))

  # Compute delta
  let deltaRes = aes_ctr(delta_aes_key, delta_iv, payload)
  if deltaRes.isErr:
    return err("Error in aes: " & deltaRes.error)
  let delta_prime = deltaRes.get()

  # Compute B
  var
    paddingLength: int
    zeroPadding: seq[byte]
  paddingLength = (t + 1) * k
  zeroPadding = newSeq[byte](paddingLength)

  let BRes = aes_ctr(beta_aes_key, beta_iv, beta & zeroPadding)
  if BRes.isErr:
    return err("Error in aes: " & BRes.error)
  let B = BRes.get()

  # Check if B has the required prefix for the original message
  paddingLength = (((t + 1) * (r - L)) + t + 2) * k
  zeroPadding = newSeq[byte](paddingLength)

  if B[0 .. paddingLength - 1] == zeroPadding:
    let deserializeRes = deserializeMessage(delta_prime)
    if deserializeRes.isErr:
      return err("Message deserialization error: " & deserializeRes.error)
    let msgPow = getMessage(deserializeRes.get())

    let verRes = verifyPow(msgPow)
    if verRes.isErr:
      return err("Error in PoW verification: " & verRes.error)

    if verRes.get():
      return ok((Hop(), @[], msgPow[0 .. messageSize - 1], Success))
    else:
      return ok((Hop(), @[], @[], InvalidPoW))
  else:
    # Extract routing information from B
    let deserializeRes = deserializeRoutingInfo(B)
    if deserializeRes.isErr:
      return err("Routing info deserialization error: " & deserializeRes.error)

    let (address, delay, gamma_prime, beta_prime) = getRoutingInfo(deserializeRes.get())

    # Compute alpha
    let blinderRes = bytesToFieldElement(sha256_hash(alpha & sBytes))
    if blinderRes.isErr:
      return err("Error in bytes to field element conversion: " & blinderRes.error)
    let blinder = blinderRes.get()

    let alphaRes = bytesToFieldElement(alpha)
    if alphaRes.isErr:
      return err("Error in bytes to field element conversion: " & alphaRes.error)

    let alpha_prime = multiplyPointWithScalars(alphaRes.get(), [blinder])

    # Serialize sphinx packet
    let sphinxPkt = initSphinxPacket(
      initHeader(fieldElementToBytes(alpha_prime), beta_prime, gamma_prime), delta_prime
    )

    let serializeRes = serializeSphinxPacket(sphinxPkt)
    if serializeRes.isErr:
      return err("Sphinx packet serialization error: " & serializeRes.error)

    return ok((address, delay, serializeRes.get(), Success))
