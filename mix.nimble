# mix.nimble
version       = "0.1.0"
author        = "Akshaya"
description   = "A custom Mix Protocol"
license       = "MIT"

# Dependencies
requires "nim >= 2.0.8"
requires "nimcrypto >= 0.6.0"
requires "libp2p >= 1.4.0"
requires "protobuf_serialization >= 0.3.0"
requires "serialization >= 0.2.2"

# Set the source directory
srcDir = "src"

task test, "Run the test suite":
  exec "nim c -r --path:src tests/test_crypto.nim"
  exec "nim c -r --path:src tests/test_curve25519.nim"
  exec "nim c -r --path:src tests/test_pow.nim"
  exec "nim c -r --path:src tests/test_serialization.nim"