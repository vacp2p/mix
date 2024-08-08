import ../src/curve25519
import unittest, pkg/libp2p/crypto/curve25519

# Helper function for non-zero check
proc isNotZero(key: FieldElement): bool =
  for byte in key:
    if byte != 0:
      return true
  return false

suite "Curve25519 Tests":
  
  test "TestGenerateKey":
    var privateKey, publicKey: FieldElement
    (privateKey, publicKey) = generateKeyPair()

    # Assert the length of the keys
    assert fieldElementToBytes(privateKey).len == FieldElementSize, "Private key size must be 32 bytes" 
    assert fieldElementToBytes(publicKey).len == FieldElementSize, "Public key size must be 32 bytes" 
    
    # Assert that the keys are not empty (i.e., not all zeros)
    assert privateKey.isNotZero(), "Private key is empty"
    assert publicKey.isNotZero(), "Public key is empty"
    
    # Verify the public key derived from private key
    let derivedPublicKey = multiplyBasePointWithScalars(@[privateKey])
    assert compareFieldElements(publicKey, derivedPublicKey), "Public key must be derived correctly"
    
  test "TestCommutativity":
    # Test commutativity: (g^x1)^x2 == (g^x2)^x1
  
    let x1 = generateRandomFieldElement()
    let x2 = generateRandomFieldElement()

    # Calculate (g^x1)^x2
    var res1 = multiplyBasePointWithScalars(@[x1, x2])

    # Calculate g^x2
    let intermediate = public(x2)

    # Calculate (g^x2)^x1
    var res2 = multiplyPointWithScalars(intermediate, @[x1])

    # Assert if results are equal
    assert compareFieldElements(res1, res2), "Field element operations must be commutative"
