import ../src/crypto
import unittest, nimcrypto

suite "cryptographic_functions_tests":

    test "aes_ctr_encrypt_decrypt":
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

    test "sha256_hash_computation":
        # Define test data
        let data: seq[byte] = cast[seq[byte]]("thisisdata")
        
        # Expected SHA-256 hash (hexadecimal representation)
        let expectedHashHex = "b53a20ecf0814267a83be82f941778ffda4b85fbf93a07847539f645ff5f1b9b"
        let expectedHash = fromHex(expectedHashHex)
        
        # Compute hash
        let hash = sha256_hash(data)
        
        # Assertions
        assert hash == expectedHash, "SHA-256 hash does not match the expected hash"

    test "kdf_computation":
        # Define test key
        let key: seq[byte] = cast[seq[byte]]("thisiskey")
        
        # Expected 16-byte hash derived from the key
        let expectedKdfHex = "37c9842d37dc404854428a0a3554dcaa"
        let expectedKdf = fromHex(expectedKdfHex)
        
        # Compute derived key
        let derivedKey = kdf(key)
        
        # Assertions
        assert derivedKey == expectedKdf, "Derived key does not match the expected key"

    test "hmac_computation":
        # Define test key and data
        let key: seq[byte] = cast[seq[byte]]("thisiskey")
        let data: seq[byte] = cast[seq[byte]]("thisisdata")
        
        # Expected HMAC (hexadecimal representation)
        let expectedHmacHex = "b075dd302655e085d35e8cef5dfdf101"
        let expectedHmac = fromHex(expectedHmacHex)
        
        # Compute HMAC
        let hmacResult = hmac(key, data)
        
        # Assertions
        assert hmacResult == expectedHmac, "HMAC does not match the expected HMAC"

    test "aes_ctr_empty_data":
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

    test "sha256_hash_empty_data":
        # Define test data
        let emptyData: array[0, byte] = []
        let expectedHashHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" # SHA-256 hash of empty input
        let expectedHash = fromHex(expectedHashHex)
        
        # Compute hash
        let hash = sha256_hash(emptyData)
        
        # Assertions
        assert hash == expectedHash, "SHA-256 hash of empty data does not match the expected hash"

    test "kdf_empty_key":
        # Define test data
        let emptyKey: array[0, byte] = []
        let expectedKdfHex = "e3b0c44298fc1c149afbf4c8996fb924" # SHA-256 hash of empty key truncated
        let expectedKdf = fromHex(expectedKdfHex)
        
        # Compute derived key
        let derivedKey = kdf(emptyKey)
        
        # Assertions
        assert derivedKey == expectedKdf, "Derived key from empty key does not match the expected key"

    test "hmac_empty_key_and_data":
        # Define test data
        let emptyKey: array[0, byte] = []
        let emptyData: array[0, byte] = []
        let expectedHmacHex = "b613679a0814d9ec772f95d778c35fc5" # SHA-256 HMAC of empty key and data
        let expectedHmac = fromHex(expectedHmacHex)
        
        # Compute HMAC
        let hmacResult = hmac(emptyKey, emptyData)
        
        # Assertions
        assert hmacResult == expectedHmac, "HMAC of empty key and data does not match the expected HMAC"

    test "aes_ctr_start_index_zero_index":
        # Define test data
        let key = cast[array[16, byte]]("thisis16byteskey")
        let iv = cast[array[16, byte]]("thisis16bytesiv!")
        let data: seq[byte] = cast[seq[byte]]("thisisdata")
        
        # Encrypt starting from index 0 (should be the same as full data encryption)
        let startIndex = 0
        let encrypted = aes_ctr_start_index(key, iv, data, startIndex)
        
        # Encrypt the whole data with the original IV
        let expected = aes_ctr(key, iv, data)
        
        # Assertions
        assert encrypted == expected, "Encrypted data with start index 0 should match the full AES-CTR encryption"

    test "aes_ctr_start_index_empty_data":
        # Define test data
        let key = cast[array[16, byte]]("thisis16byteskey")
        let iv = cast[array[16, byte]]("thisis16bytesiv!")
        let emptyData: array[0, byte] = []
        
        # Encrypt from start index 0 on empty data
        let startIndex = 0
        let encrypted = aes_ctr_start_index(key, iv, emptyData, startIndex)

        # Encrypting empty data should result in empty data
        assert encrypted == emptyData, "Encrypted empty data with start index 0 should be empty"
    
    test "aes_ctr_start_index_middle":
        # Define test data
        let key = cast[array[16, byte]]("thisis16byteskey")
        let iv = cast[array[16, byte]]("thisis16bytesiv!")
        let data: seq[byte] = cast[seq[byte]]("thisisverylongdata")

        # Encrypt starting from index 16
        let startIndex = 16
        let encrypted2 = aes_ctr_start_index(key, iv, data[startIndex..^1], startIndex)

        # Encrypt the data up to index 15
        let encrypted1 = aes_ctr(key, iv, data[0..startIndex-1])
        
        # Encrypt the whole data with the original IV
        let expected = aes_ctr(key, iv, data)
        
        # Assertions
        assert encrypted1 & encrypted2 == expected, "Encrypted data with start index should match the full AES-CTR encryption"