import unittest
import ../src/utils
import ../src/config

suite "Utils tests":
  test "multi_addr_conversion":
    let multiAddrs = [
      "/ip4/127.0.0.1/tcp/4242/mix/Ae7DAz7oNKMfyFTH42ecN6nf4gWf68uMckcgvG713K5x",
      "/ip4/192.168.1.1/quic/8080/mix/2xuj1pmzvdHWctNgNbAtP9iVirHjnaRhkHpZYVpRhRPH",
      "/ip4/10.0.0.1/tcp/1234/mix/CVUQD1jTxZGro6PZvdzS3sJfMwfgMGuNY4KKvNXGPzSC"
    ]

    for multiAddr in multiAddrs:
      let multiAddrBytes = multiAddrToBytes(multiAddr)
      check multiAddrBytes.len == addrSize
      let multiAddrString = bytesToMultiAddr(multiAddrBytes)
      check multiAddrString == multiAddr

  test "invalid_protocol":
    expect AssertionDefect:
      discard multiAddrToBytes("/ip4/127.0.0.1/udp/4242/mix/Ae7DAz7oNKMfyFTH42ecN6nf4gWf68uMckcgvG713K5x")

  test "invalid_peerid_length":
    expect AssertionDefect:
      discard multiAddrToBytes("/ip4/127.0.0.1/tcp/4242/mix/QmTooShort")

  test "invalid_addr_length":
    let invalidBytes = newSeq[byte](addrSize - 1)
    expect AssertionDefect:
      discard bytesToMultiAddr(invalidBytes)