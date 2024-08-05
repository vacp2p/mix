import nimcrypto, sequtils

# This function processes 'data' using AES in CTR mode.
# For CTR mode, the same function handles both encryption and decryption.
proc aes_ctr*(key, iv, data: openArray[byte]): seq[byte] =
    assert key.len == 16, "Key must be 16 bytes for AES-128"
    assert iv.len == 16, "IV must be 16 bytes for AES-128"

    var ctx: CTR[aes128]
    ctx.init(key, iv)

    var output = newSeq[byte](data.len)
    ctx.encrypt(data, output)

    ctx.clear()
    return output

# This function hashes 'data' using SHA-256.
proc sha256_hash*(data: openArray[byte]): seq[byte] =
    return toSeq(sha256.digest(data).data)

# This function returns the hash of 'key' truncated to 16 bytes.
proc kdf*(key: openArray[byte]): seq[byte] =
    let hash = sha256_hash(key.toSeq)
    result = hash[0..15]

# This function computes a HMAC for 'data' using given 'key'.
proc hmac*(key, data: openArray[byte]): seq[byte] =
    return toSeq(sha256.hmac(key, data).data)