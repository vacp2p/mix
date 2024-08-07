import ../src/crypto
import unittest, nimcrypto

suite "Cryptographic Functions Tests":

    test "aes_ctr function test":
        # Define test data
        let key = cast[array[16, byte]]("thisis16byteskey")
        let iv = cast[array[16, byte]]("thisis16bytesiv!")
        let data: seq[byte] = cast[seq[byte]]("thisisdata")
        
        # Encrypt data
        let encrypted = aes_ctr(key, iv, data)
        
        # Decrypt data (should return to original)
        let decrypted = aes_ctr(key, iv, encrypted)
        
        # Assertions
        assert data == decrypted, "Decrypted data does not match the original data"
        assert encrypted != data, "Encrypted data should not match the original data"

    test "sha256_hash function test":
        # Define test data
        let data: seq[byte] = cast[seq[byte]]("thisisdata")
        
        # Expected SHA-256 hash (hexadecimal representation)
        let expectedHashHex = "b53a20ecf0814267a83be82f941778ffda4b85fbf93a07847539f645ff5f1b9b"
        let expectedHash = fromHex(expectedHashHex)
        
        # Compute hash
        let hash = sha256_hash(data)
        
        # Assertions
        assert hash == expectedHash, "SHA-256 hash does not match the expected hash"

    test "kdf function test":
        # Define test key
        let key: seq[byte] = cast[seq[byte]]("thisiskey")
        
        # Expected 16-byte hash derived from the key
        let expectedKdfHex = "37c9842d37dc404854428a0a3554dcaa"
        let expectedKdf = fromHex(expectedKdfHex)
        
        # Compute derived key
        let derivedKey = kdf(key)
        
        # Assertions
        assert derivedKey == expectedKdf, "Derived key does not match the expected key"

    test "hmac function test":
        # Define test key and data
        let key: seq[byte] = cast[seq[byte]]("thisiskey")
        let data: seq[byte] = cast[seq[byte]]("thisisdata")
        
        # Expected HMAC (hexadecimal representation)
        let expectedHmacHex = "b075dd302655e085d35e8cef5dfdf101e0701c21bd00baf0e568d5d556c1150c"
        let expectedHmac = fromHex(expectedHmacHex)
        
        # Compute HMAC
        let hmacResult = hmac(key, data)
        
        # Assertions
        assert hmacResult == expectedHmac, "HMAC does not match the expected HMAC"

    test "aes_ctr empty data test":
        # Define test data
        let key = cast[array[16, byte]]("thisis16byteskey")
        let iv = cast[array[16, byte]]("thisis16bytesiv!")
        let emptyData: array[0, byte] = []
        
        # Encrypt data
        let encrypted = aes_ctr(key, iv, emptyData)

        # Decrypt data
        let decrypted = aes_ctr(key, iv, encrypted)
        
        # Assertions
        assert emptyData == decrypted, "Decrypted empty data does not match the original empty data"
        assert encrypted == emptyData, "Encrypted empty data should still be empty"

    test "sha256_hash empty data test":
        # Define test data
        let emptyData: array[0, byte] = []
        let expectedHashHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" # SHA-256 hash of empty input
        let expectedHash = fromHex(expectedHashHex)
        
        # Compute hash
        let hash = sha256_hash(emptyData)
        
        # Assertions
        assert hash == expectedHash, "SHA-256 hash of empty data does not match the expected hash"

    test "kdf empty key test":
        # Define test data
        let emptyKey: array[0, byte] = []
        let expectedKdfHex = "e3b0c44298fc1c149afbf4c8996fb924" # SHA-256 hash of empty key truncated
        let expectedKdf = fromHex(expectedKdfHex)
        
        # Compute derived key
        let derivedKey = kdf(emptyKey)
        
        # Assertions
        assert derivedKey == expectedKdf, "Derived key from empty key does not match the expected key"

    test "hmac empty key and data test":
        # Define test data
        let emptyKey: array[0, byte] = []
        let emptyData: array[0, byte] = []
        let expectedHmacHex = "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad" # SHA-256 HMAC of empty key and data
        let expectedHmac = fromHex(expectedHmacHex)
        
        # Compute HMAC
        let hmacResult = hmac(emptyKey, emptyData)
        
        # Assertions
        assert hmacResult == expectedHmac, "HMAC of empty key and data does not match the expected HMAC"