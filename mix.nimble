version       = "0.1.0"
author        = "Akshaya"
description   = "A custom Mix Protocol"
license       = "MIT"

# Dependencies
requires "chronos >= 4.0.3"
requires "libp2p >= 1.5.0"
requires "nim >= 2.0.8"
requires "nimcrypto >= 0.6.0"
requires "serialization >= 0.2.2"

# Set the source directory
srcDir = "src"

task test, "Run the test suite":
  exec "nim c -r tests/test_crypto.nim"
  exec "nim c -r tests/test_curve25519.nim"
  exec "nim c -r tests/test_pow.nim"
  exec "nim c -r tests/test_serialization.nim"
  exec "nim c -r tests/test_sphinx.nim"
  exec "nim c -r tests/test_tag_manager.nim"