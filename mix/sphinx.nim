import results, sequtils
import nimcrypto/sysrand
import ./[config, crypto, curve25519, serialization, tag_manager]

# Define possible outcomes of processing a Sphinx packet
type ProcessingStatus* = enum
  Exit # Packet processed successfully at exit
  Success # Packet processed successfully
  Reply # Packet processed successfully at exit; a reply message
  Duplicate # Packet was discarded due to duplicate tag
  InvalidMAC
    # Packet was discarded due to MAC verification failure

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

  let x = generateRandomFieldElement().valueOr:
    return err("Generate field element error: " & error)

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

    let blinder = bytesToFieldElement(
      sha256_hash(fieldElementToBytes(alpha) & fieldElementToBytes(secret))
    ).valueOr:
      return err("Error in bytes to field element conversion: " & error)

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

# Function to compute betas and gammas
proc computeBetaGamma(
    s: seq[seq[byte]], hop: openArray[Hop], delay: openArray[seq[byte]]
): Result[(seq[byte], seq[byte]), string] =
  let sLen = s.len
  var
    beta: seq[byte]
    gamma: seq[byte]

  # Compute filler strings
  let filler = computeFillerStrings(s).valueOr:
    return err("Error in filler generation: " & error)

  for i in countdown(sLen - 1, 0):
    # Derive AES key, MAC key, and IV
    let
      beta_aes_key = kdf(deriveKeyMaterial("aes_key", s[i]))
      mac_key = kdf(deriveKeyMaterial("mac_key", s[i]))
      beta_iv = kdf(deriveKeyMaterial("iv", s[i]))

    # Compute Beta and Gamma
    if i == sLen - 1:
      let
        paddingLength = (((t + 1) * (r - L)) + t + 2) * k
        zeroPadding = newSeq[byte](paddingLength)

      let aesRes = aes_ctr(beta_aes_key, beta_iv, zeroPadding).valueOr:
        return err("Error in aes: " & error)
      beta = aesRes & filler
    else:
      let routingInfo = initRoutingInfo(
        hop[i + 1], delay[i + 1], gamma, beta[0 .. (((r * (t + 1)) - t) * k) - 1]
      )

      let serializeRes = serializeRoutingInfo(routingInfo).valueOr:
        return err("Routing info serialization error: " & error)

      let betaRes = aes_ctr(beta_aes_key, beta_iv, serializeRes)
      if betaRes.isErr:
        return err("Error in aes: " & betaRes.error)
      beta = betaRes.get()

    gamma = toseq(hmac(mac_key, beta))

  return ok((beta, gamma))

# Function to compute deltas
proc computeDelta(s: seq[seq[byte]], msg: Message): Result[seq[byte], string] =
  let sLen = s.len
  var delta: seq[byte]

  for i in countdown(sLen - 1, 0):
    # Derive AES key and IV
    let
      delta_aes_key = kdf(deriveKeyMaterial("delta_aes_key", s[i]))
      delta_iv = kdf(deriveKeyMaterial("delta_iv", s[i]))

    # Compute Delta
    if i == sLen - 1:
      let serializeRes = serializeMessage(msg).valueOr:
        return err("Message serialization error: " & error)

      let deltaRes = aes_ctr(delta_aes_key, delta_iv, serializeRes)
      if deltaRes.isErr:
        return err("Error in aes: " & deltaRes.error)
      delta = deltaRes.get()
    else:
      let deltaRes = aes_ctr(delta_aes_key, delta_iv, delta)
      if deltaRes.isErr:
        return err("Error in aes: " & deltaRes.error)
      delta = deltaRes.get()

  return ok(delta)

proc createSURB*(
    publicKeys: openArray[FieldElement],
    delay: openArray[seq[byte]],
    hop: openArray[Hop],
): Result[(Hop, Header, seq[seq[byte]], seq[byte]), string] =
  # Compute alpha and shared secrets
  let res1 = computeAlpha(publicKeys)
  if res1.isErr:
    return err("Error in alpha generation: " & res1.error)
  let (alpha_0, s) = res1.get()

  # Compute beta and gamma
  let res2 = computeBetaGamma(s, hop, delay)
  if res2.isErr:
    return err("Error in beta and gamma generation: " & res2.error)
  let (beta_0, gamma_0) = res2.get()

  # Generate key
  var key = newSeq[byte](k)
  discard randomBytes(key)

  return ok((hop[0], initHeader(alpha_0, beta_0, gamma_0), s, key))

proc useSURB*(header: Header, key: seq[byte], msg: Message): Result[seq[byte], string] =
  # Derive AES key and IV
  let
    delta_aes_key = kdf(deriveKeyMaterial("delta_aes_key", key))
    delta_iv = kdf(deriveKeyMaterial("delta_iv", key))

  # Compute Delta
  let serializeMsg = serializeMessage(msg).valueOr:
    return err("Message serialization error: " & error)

  let delta = aes_ctr(delta_aes_key, delta_iv, serializeMsg).valueOr:
    return err("Error in aes: " & error)

  # Serialize sphinx packet
  let sphinxPacket = initSphinxPacket(header, delta)

  let serializeRes = serializeSphinxPacket(sphinxPacket).valueOr:
    return err("Sphinx packet serialization error: " & error)

  return ok(serializeRes)

proc processReply*(
    key: seq[byte], s: seq[seq[byte]], delta_prime: seq[byte]
): Result[seq[byte], string] =
  var delta = delta_prime[0 ..^ 1]

  for i in 0 .. s.len:
    var key_prime: seq[byte]

    if i == 0:
      key_prime = key
    else:
      key_prime = s[i - 1]

    # Derive AES key and IV
    let
      delta_aes_key = kdf(deriveKeyMaterial("delta_aes_key", key_prime))
      delta_iv = kdf(deriveKeyMaterial("delta_iv", key_prime))

    let deltaRes = aes_ctr(delta_aes_key, delta_iv, delta)
    if deltaRes.isErr:
      return err("Error in aes: " & deltaRes.error)
    delta = deltaRes.get()

  let deserializeRes = deserializeMessage(delta).valueOr:
    return err("Message deserialization error: " & error)
  let msg = getMessage(deserializeRes)

  return ok(msg)

proc wrapInSphinxPacket*(
    msg: Message,
    publicKeys: openArray[FieldElement],
    delay: openArray[seq[byte]],
    hop: openArray[Hop],
): Result[seq[byte], string] =
  # Compute alpha and shared secrets
  let res1 = computeAlpha(publicKeys)
  if res1.isErr:
    return err("Error in alpha generation: " & res1.error)
  let (alpha_0, s) = res1.get()

  # Compute beta and gamma
  let res2 = computeBetaGamma(s, hop, delay)
  if res2.isErr:
    return err("Error in beta and gamma generation: " & res2.error)
  let (beta_0, gamma_0) = res2.get()

  # Compute delta
  let delta_0 = computeDelta(s, msg).valueOr:
    return err("Error in delta generation: " & error)

  # Serialize sphinx packet
  let sphinxPacket = initSphinxPacket(initHeader(alpha_0, beta_0, gamma_0), delta_0)

  let serializeRes = serializeSphinxPacket(sphinxPacket).valueOr:
    return err("Sphinx packet serialization error: " & error)

  return ok(serializeRes)

proc processSphinxPacket*(
    serSphinxPacket: seq[byte], privateKey: FieldElement, tm: var TagManager
): Result[(Hop, seq[byte], seq[byte], ProcessingStatus), string] =
  # Deserialize the Sphinx packet
  let deserializeRes = deserializeSphinxPacket(serSphinxPacket).valueOr:
    return err("Sphinx packet deserialization error: " & error)

  let
    (header, payload) = getSphinxPacket(deserializeRes)
    (alpha, beta, gamma) = getHeader(header)

  # Compute shared secret
  let alphaRes = bytesToFieldElement(alpha).valueOr:
    return err("Error in bytes to field element conversion: " & error)

  let
    s = multiplyPointWithScalars(alphaRes, [privateKey])
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
  let delta_prime = aes_ctr(delta_aes_key, delta_iv, payload).valueOr:
    return err("Error in aes: " & error)

  # Compute B
  var
    paddingLength: int
    zeroPadding: seq[byte]
  paddingLength = (t + 1) * k
  zeroPadding = newSeq[byte](paddingLength)

  let B = aes_ctr(beta_aes_key, beta_iv, beta & zeroPadding).valueOr:
    return err("Error in aes: " & error)

  # Check if B has the required prefix for the original message
  paddingLength = (((t + 1) * (r - L)) + t + 2) * k
  zeroPadding = newSeq[byte](paddingLength)

  if B[0 .. paddingLength - 1] == zeroPadding:
    if delta_prime[0 .. (k - 1)] == newSeq[byte](k):
      let deserializeRes = deserializeMessage(delta_prime).valueOr:
        return err("Message deserialization error: " & error)
      let msg = getMessage(deserializeRes)

      return ok((Hop(), @[], msg[0 .. messageSize - 1], Exit))
    else:
      return ok((Hop(), @[], delta_prime, Reply))
  else:
    # Extract routing information from B
    let deserializeRes = deserializeRoutingInfo(B).valueOr:
      return err("Routing info deserialization error: " & error)

    let (address, delay, gamma_prime, beta_prime) = getRoutingInfo(deserializeRes)

    # Compute alpha
    let blinder = bytesToFieldElement(sha256_hash(alpha & sBytes)).valueOr:
      return err("Error in bytes to field element conversion: " & error)

    let alphaRes = bytesToFieldElement(alpha).valueOr:
      return err("Error in bytes to field element conversion: " & error)

    let alpha_prime = multiplyPointWithScalars(alphaRes, [blinder])

    # Serialize sphinx packet
    let sphinxPkt = initSphinxPacket(
      initHeader(fieldElementToBytes(alpha_prime), beta_prime, gamma_prime), delta_prime
    )

    let serializeRes = serializeSphinxPacket(sphinxPkt).valueOr:
      return err("Sphinx packet serialization error: " & error)

    return ok((address, delay, serializeRes, Success))
