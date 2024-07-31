# mix.nimble
version       = "0.1.0"
author        = "Akshaya"
description   = "A custom Mix Protocol"
license       = "MIT"

# Dependencies
requires "nim >= 1.6.0"
requires "nimcrypto"
requires "libp2p >= 1.4.0"

# Set the source directory
srcDir = "src"

# Tasks
task test, "Run the test suite":
  exec "nim c -r --path:src tests/test_crypto.nim"
  exec "nim c -r --path:src tests/test_curve25519.nim"
