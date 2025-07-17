version = "0.1.0"
author = "Akshaya"
description = "A custom Mix Protocol"
license = "MIT"

# Dependencies
requires "stew >= 0.3.0"
requires "chronos >= 4.0.3"
requires "https://github.com/vacp2p/nim-libp2p#64c9cf1b9e69a6d1da9f430ffb1f91e949658f28"
requires "nim >= 1.6.0"
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
  runTest("tests")
