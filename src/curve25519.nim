import pkg/libp2p/crypto/curve25519
import bearssl/rand

const FieldElementSize* = Curve25519KeySize

type FieldElement* = Curve25519Key

# Convert bytes to FieldElement
proc bytesToFieldElement*(bytes: openArray[byte]): FieldElement =
  assert bytes.len == FieldElementSize, "Field element size must be 32 bytes"
  intoCurve25519Key(bytes)

# Convert FieldElement to bytes
proc fieldElementToBytes*(fe: FieldElement): seq[byte] =
  fe.getBytes()

# Generate a random FieldElement
proc generateRandomFieldElement*(): FieldElement =
    let rng = HmacDrbgContext.new()
    assert not rng.isNil, "Failed to creat HmacDrbgContext with system randomness"
    Curve25519Key.random(rng[])

# Generate a key pair (private key and public key are both FieldElements)
proc generateKeyPair*(): tuple[privateKey, publicKey: FieldElement] =
  let privateKey = generateRandomFieldElement()
  let publicKey = public(privateKey)
  (privateKey, publicKey)

# Multiply a given Curve25519 point with a set of scalars
proc multiplyPointWithScalars*(point: FieldElement, scalars: openArray[FieldElement]): FieldElement =
  var res = point
  for scalar in scalars:
    Curve25519.mul(res, scalar)
  res

# Multiply the Curve25519 base point with a set of scalars
proc multiplyBasePointWithScalars*(scalars: openArray[FieldElement]): FieldElement =
    assert scalars.len > 0, "Atleast one scalar must be provided"
    var res: FieldElement = public(scalars[0])  # Use the predefined base point
    for i in 1..<scalars.len:
        Curve25519.mul(res, scalars[i])  # Multiply with each scalar
    res

# Compare two FieldElements
proc compareFieldElements*(a, b: FieldElement): bool =
  a == b