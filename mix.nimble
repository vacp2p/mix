version = "0.1.0"
author = "Akshaya"
description = "A custom Mix Protocol"
license = "MIT"

# Dependencies
requires "chronos >= 4.0.3"
requires "libp2p#5494c345899ce7470323e43134d7189f62b93381"
requires "https://github.com/status-im/nim-quic.git#0e4677b3e8cafdaaaba52de59164a8e64ed3906e"
  # This is a libp2p dependency, but we need a ref that contains a specific ref that is not yet merged
  # Also, this differs with the nim-quic ref specified in libp2p but somehow no conflicts happen. 
  # Likely because this ref is a fast-forward from the libp2p ref
requires "nim >= 2.0.8"
requires "nimcrypto >= 0.6.0"
requires "serialization >= 0.2.2"
requires "unittest2"

# Set the source directory
srcDir = "src"
const TEST_DIRECTORY = "tests"

import strformat

proc runTest(filename: string, shouldRemoveTestBinary: bool = true) =
  var execStr = "nim c -r"
  exec fmt"{execStr} {TEST_DIRECTORY}/{filename}"
  if shouldRemoveTestBinary:
    rmFile fmt"{TEST_DIRECTORY}/{filename.toExe()}"

task test, "Run the test suite":
  runTest("test_crypto")
  runTest("test_curve25519")
  runTest("test_fragmentation")
  runTest("test_mix_node")
  runTest("test_mix_protocol")
  runTest("test_pow")
  runTest("test_seqno_generator")
  runTest("test_serialization")
  runTest("test_sphinx")
  runTest("test_tag_manager")
  runTest("test_utils")
