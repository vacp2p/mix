version = "0.1.0"
author = "Akshaya"
description = "A custom Mix Protocol"
license = "MIT"
skipDirs = @["tests", "examples"]

# Dependencies
requires "stew >= 0.3.0"
requires "chronos >= 4.0.3"
requires "https://github.com/vacp2p/nim-libp2p#f83638eb82f04bcdd2e98ef1bf8f52d9e13250c0"
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
