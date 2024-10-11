import unittest
import ../src/utils
import ../src/config

suite "Utils tests":
  test "multi_addr_conversion":
    let multiAddrs = [
      "/ip4/127.0.0.1/tcp/4242/p2p/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC",
      "/ip4/192.168.1.1/quic/8080/p2p/16Uiu2HAm6WNzw8AssyPscYYi8x1bY5wXyQrGTShRH75bh5dPCjBQ",
      "/ip4/10.0.0.1/tcp/1234/p2p/16Uiu2HAmDHw4mwBdEjxjJPhrt8Eq1kvDjXAuwkqCmhNiz363AFV2"
    ]

    for multiAddr in multiAddrs:
      let multiAddrBytes = multiAddrToBytes(multiAddr)
      check multiAddrBytes.len == addrSize
      let multiAddrString = bytesToMultiAddr(multiAddrBytes)
      check multiAddrString == multiAddr

  test "invalid_protocol":
    expect AssertionDefect:
      discard multiAddrToBytes("/ip4/127.0.0.1/udp/4242/p2p/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC")

  test "invalid_peerid_length":
    expect AssertionDefect:
      discard multiAddrToBytes("/ip4/127.0.0.1/tcp/4242/p2p/16Uiu2HAmFk")

  test "invalid_addr_length":
    let invalidBytes = newSeq[byte](addrSize - 1)
    expect AssertionDefect:
      discard bytesToMultiAddr(invalidBytes)