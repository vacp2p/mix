import results, sequtils
import ./[config, crypto, curve25519, serialization, tag_manager]

# Define possible outcomes of processing a Sphinx packet
type ProcessingStatus* = enum
  Exit # Packet processed successfully at exit
  Intermediate # Packet processed successfully at intermediate node
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

# Function to compute betas, gammas, and deltas
proc computeBetaGammaDelta(
    s: seq[seq[byte]],
    hop: openArray[Hop],
    msg: Message,
    delay: openArray[seq[byte]],
    destHop: Hop,
): Result[(seq[byte], seq[byte], seq[byte]), string] = # TODO: name tuples
  let sLen = s.len
  var
    beta: seq[byte]
    gamma: seq[byte]
    delta: seq[byte]

  # Compute filler strings
  let filler = computeFillerStrings(s).valueOr:
    return err("Error in filler generation: " & error)

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
      let paddingLength = (((t + 1) * (r - L)) + 2) * k
      let destBytes = ?destHop.serialize()
      let padding = destBytes & delay[i] & newSeq[byte](paddingLength)

      let aesRes = aes_ctr(beta_aes_key, beta_iv, padding).valueOr:
        return err("Error in aes: " & error)
      beta = aesRes & filler

      let serializedMsg = msg.serialize().valueOr:
        return err("Message serialization error: " & error)

      delta = aes_ctr(delta_aes_key, delta_iv, serializedMsg).valueOr:
        return err("Error in aes: " & error)
    else:
      let routingInfo = RoutingInfo.init(
        hop[i + 1], delay[i + 1], gamma, beta[0 .. (((r * (t + 1)) - t) * k) - 1]
      )

      let serializedRoutingInfo = routingInfo.serialize().valueOr:
        return err("Routing info serialization error: " & error)

      beta = aes_ctr(beta_aes_key, beta_iv, serializedRoutingInfo).valueOr:
        return err("Error in aes: " & error)

      delta = aes_ctr(delta_aes_key, delta_iv, delta).valueOr:
        return err("Error in aes: " & error)

    gamma = toSeq(hmac(mac_key, beta))

  return ok((beta, gamma, delta))

proc wrapInSphinxPacket*(
    msg: Message,
    publicKeys: openArray[FieldElement],
    delay: openArray[seq[byte]],
    hop: openArray[Hop],
    destHop: Hop,
): Result[seq[byte], string] =
  # Compute alphas and shared secrets
  let (alpha_0, s) = computeAlpha(publicKeys).valueOr:
    return err("Error in alpha generation: " & error)

  # Compute betas, gammas, and deltas
  let (beta_0, gamma_0, delta_0) = computeBetaGammaDelta(s, hop, msg, delay, destHop).valueOr:
    return err("Error in beta, gamma, and delta generation: " & error)

  # Serialize sphinx packet
  let sphinxPacket = SphinxPacket.init(Header.init(alpha_0, beta_0, gamma_0), delta_0)

  let serialized = sphinxPacket.serialize().valueOr:
    return err("Sphinx packet serialization error: " & error)

  return ok(serialized)

proc processSphinxPacket*(
    serSphinxPacket: seq[byte], privateKey: FieldElement, tm: var TagManager
): Result[(Hop, seq[byte], seq[byte], ProcessingStatus), string] = # TODO: named touple
  # Deserialize the Sphinx packet
  let sphinxPacket = SphinxPacket.deserialize(serSphinxPacket).valueOr:
    return err("Sphinx packet deserialization error: " & error)

  let
    (header, payload) = sphinxPacket.getSphinxPacket()
    (alpha, beta, gamma) = getHeader(header)

  # Compute shared secret
  let alphaFE = bytesToFieldElement(alpha).valueOr:
    return err("Error in bytes to field element conversion: " & error)

  let
    s = multiplyPointWithScalars(alphaFE, [privateKey])
    sBytes = fieldElementToBytes(s)

  # Check if the tag has been seen
  if isTagSeen(tm, s):
    return ok((Hop(), @[], @[], Duplicate))

  # Compute MAC
  let mac_key = kdf(deriveKeyMaterial("mac_key", sBytes))

  if not (toSeq(hmac(mac_key, beta)) == gamma):
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
  paddingLength = (((t + 1) * (r - L)) + 2) * k
  zeroPadding = newSeq[byte](paddingLength)

  if B[(t * k) .. (t * k) + paddingLength - 1] == zeroPadding:
    let msg = Message.deserialize(delta_prime).valueOr:
      return err("Message deserialization error: " & error)
    let content = msg.getContent()
    let hop = Hop.deserialize(B[0 .. addrSize - 1]).valueOr:
      return err(error)
    return ok((hop, B[addrSize .. ((t * k) - 1)], content[0 .. messageSize - 1], Exit))
  else:
    # Extract routing information from B
    let routingInfo = RoutingInfo.deserialize(B).valueOr:
      return err("Routing info deserialization error: " & error)

    let (address, delay, gamma_prime, beta_prime) = routingInfo.getRoutingInfo()

    # Compute alpha
    let blinder = bytesToFieldElement(sha256_hash(alpha & sBytes)).valueOr:
      return err("Error in bytes to field element conversion: " & error)

    let alphaFE = bytesToFieldElement(alpha).valueOr:
      return err("Error in bytes to field element conversion: " & error)

    let alpha_prime = multiplyPointWithScalars(alphaFE, [blinder])

    # Serialize sphinx packet
    let sphinxPkt = SphinxPacket.init(
      Header.init(fieldElementToBytes(alpha_prime), beta_prime, gamma_prime),
      delta_prime,
    )

    let serializedSP = sphinxPkt.serialize().valueOr:
      return err("Sphinx packet serialization error: " & error)

    return ok((address, delay, serializedSP, Intermediate))
