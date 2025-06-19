version = "0.1.0"
author = "Akshaya"
description = "A custom Mix Protocol"
license = "MIT"

# Dependencies
requires "chronos >= 4.0.3"
requires "https://github.com/vacp2p/nim-libp2p#poc/mix-transport"
requires "nim >= 2.0.8"
requires "nimcrypto >= 0.6.0"
requires "serialization >= 0.2.2"

# Set the source directory
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
  runTest("test_mix_message")
  runTest("test_mix_node")
  runTest("test_seqno_generator")
  runTest("test_serialization")
  runTest("test_sphinx")
  runTest("test_tag_manager")
  runTest("test_utils")
