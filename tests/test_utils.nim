import unittest
import ../src/utils
import ../src/config

suite "Utils tests":
  test "multi_addr_conversion":
    let multiAddrs = [
      "/ip4/127.0.0.1/tcp/4242/mix/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC",
      "/ip4/192.168.1.1/quic/8080/mix/16Uiu2HAm6WNzw8AssyPscYYi8x1bY5wXyQrGTShRH75bh5dPCjBQ",
      "/ip4/10.0.0.1/tcp/1234/mix/16Uiu2HAmDHw4mwBdEjxjJPhrt8Eq1kvDjXAuwkqCmhNiz363AFV2",
    ]

    for multiAddr in multiAddrs:
      let multiAddrBytes = multiAddrToBytes(multiAddr)
      check multiAddrBytes.len == addrSize
      let multiAddrString = bytesToMultiAddr(multiAddrBytes)
      check multiAddrString == multiAddr

  test "invalid_protocol":
    expect AssertionDefect:
      discard multiAddrToBytes(
        "/ip4/127.0.0.1/udp/4242/mix/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC"
      )

  test "invalid_peerid_length":
    expect AssertionDefect:
      discard multiAddrToBytes("/ip4/127.0.0.1/tcp/4242/mix/16Uiu2HAmFk")

  test "invalid_addr_length":
    let invalidBytes = newSeq[byte](addrSize - 1)
    expect AssertionDefect:
      discard bytesToMultiAddr(invalidBytes)

  test "invalid_ip_address_format":
    expect AssertionDefect:
      discard multiAddrToBytes(
        "/ip4/127.0.0/tcp/4242/mix/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC"
      )

  test "invalid_ip_address_part":
    expect AssertionDefect:
      discard multiAddrToBytes(
        "/ip4/127.0.0.256/tcp/4242/mix/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC"
      )

  test "invalid_base58_encoding":
    let result = multiAddrToBytes(
      "/ip4/127.0.0.1/tcp/4242/mix/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgV!"
    )
    assert result == newSeq[byte](), "Invalid Base58 encoding not recognized"

  test "invalid_multiaddress_format":
    expect AssertionDefect:
      discard multiAddrToBytes("/ip4/127.0.0.1/tcp/4242")

  test "invalid_port_number":
    expect AssertionDefect:
      discard multiAddrToBytes(
        "/ip4/127.0.0.1/tcp/65536/mix/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC"
      )

  test "bytes_to_uint16_conversion":
    check bytesToUInt16([0x12'u8, 0x34'u8]) == 0x1234'u16
    check bytesToUInt16([0x00'u8, 0x01'u8]) == 0x0001'u16
    check bytesToUInt16([0xFF'u8, 0xFF'u8]) == 0xFFFF'u16

  test "uint16_to_bytes_conversion":
    let value: uint16 = 0x1234
    let bytes = uint16ToBytes(value)
    check bytes == @[byte 0x12, 0x34]

  test "bytes_to_uint32_conversion":
    check bytesToUInt32([0x12'u8, 0x34'u8, 0x56'u8, 0x78'u8]) == 0x12345678'u32
    check bytesToUInt32([0x00'u8, 0x00'u8, 0x00'u8, 0x01'u8]) == 0x00000001'u32
    check bytesToUInt32([0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8]) == 0xFFFFFFFF'u32

  test "uint32_to_bytes_conversion":
    let value: uint32 = 0x12345678
    let bytes = uint32ToBytes(value)
    check bytes == @[byte 0x12, 0x34, 0x56, 0x78]

  test "uint16_bytes_roundtrip":
    let original: uint16 = 0xABCD'u16
    let bytes = uint16ToBytes(original)
    let roundtrip = bytesToUInt16(bytes)
    check roundtrip == original

  test "uint32_bytes_roundtrip":
    let original: uint32 = 0x12345678'u32
    let bytes = uint32ToBytes(original)
    let roundtrip = bytesToUInt32(bytes)
    check roundtrip == original
