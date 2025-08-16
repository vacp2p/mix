import chronicles, results, unittest
import ../src/[config, utils]

suite "Utils tests":
  test "multi_addr_conversion":
    let multiAddrs = [
      "/ip4/127.0.0.1/tcp/4242/p2p/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC",
      "/ip4/192.168.1.1/quic/8080/p2p/16Uiu2HAm6WNzw8AssyPscYYi8x1bY5wXyQrGTShRH75bh5dPCjBQ",
      "/ip4/10.0.0.1/tcp/1234/p2p/16Uiu2HAmDHw4mwBdEjxjJPhrt8Eq1kvDjXAuwkqCmhNiz363AFV2",
    ]

    for multiAddr in multiAddrs:
      let multiAddrBytesRes = multiAddrToBytes(multiAddr)
      if multiAddrBytesRes.isErr:
        error "Multiaddress to bytes conversion failed", err = multiAddrBytesRes.error
        fail()
      let multiAddrBytes = multiAddrBytesRes.get()

      if multiAddrBytes.len != ipv4AddrSize:
        error "Incorrect IPv4 address size",
          expected = ipv4AddrSize, actual = multiAddrBytes.len
        fail()

      let multiAddrStringRes = bytesToMultiAddr(multiAddrBytes)
      if multiAddrStringRes.isErr:
        error "Bytes to MultiAddr conversion failed", err = multiAddrStringRes.error
        fail()
      let multiAddrString = multiAddrStringRes.get()

      if multiAddrString != multiAddr:
        error "MultiAddr mismatch", expected = multiAddr, actual = multiAddrString
        fail()

  test "ipv6_multi_addr_conversion":
    let ipv6MultiAddrs = [
      "/ip6/::1/tcp/4242/p2p/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC",
      "/ip6/2001:db8::1/quic/8080/p2p/16Uiu2HAm6WNzw8AssyPscYYi8x1bY5wXyQrGTShRH75bh5dPCjBQ",
      "/ip6/fe80::1/tcp/1234/p2p/16Uiu2HAmDHw4mwBdEjxjJPhrt8Eq1kvDjXAuwkqCmhNiz363AFV2",
    ]

    for multiAddr in ipv6MultiAddrs:
      let multiAddrBytesRes = multiAddrToBytes(multiAddr)
      if multiAddrBytesRes.isErr:
        error "IPv6 multiaddress to bytes conversion failed",
          err = multiAddrBytesRes.error
        fail()
      let multiAddrBytes = multiAddrBytesRes.get()

      if multiAddrBytes.len != ipv6AddrSize:
        error "Incorrect IPv6 address size",
          expected = ipv6AddrSize, actual = multiAddrBytes.len
        fail()

      let multiAddrStringRes = bytesToMultiAddr(multiAddrBytes)
      if multiAddrStringRes.isErr:
        error "Bytes to IPv6 MultiAddr conversion failed",
          err = multiAddrStringRes.error
        fail()
      let multiAddrString = multiAddrStringRes.get()

      # Note: IPv6 addresses might be formatted differently when converted back
      # So we check that they parse to the same address
      let originalBytesRes = multiAddrToBytes(multiAddrString)
      if originalBytesRes.isErr:
        error "Round-trip IPv6 conversion failed", err = originalBytesRes.error
        fail()

      if originalBytesRes.get() != multiAddrBytes:
        error "IPv6 round-trip mismatch",
          original = multiAddr, roundtrip = multiAddrString
        fail()

  test "invalid_protocol":
    let res = multiAddrToBytes(
      "/ip4/127.0.0.1/udp/4242/p2p/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC"
    )
    if res.isOk:
      error "Expected error for invalid protocol, but conversion succeeded"
      fail()

  test "invalid_peerid_length":
    let res = multiAddrToBytes("/ip4/127.0.0.1/tcp/4242/p2p/16Uiu2HAmFk")
    if res.isOk:
      error "Expected error for invalid peer ID length, but conversion succeeded"
      fail()

  test "invalid_addr_length":
    let invalidBytes = newSeq[byte](addrSize - 1)
    let res = bytesToMultiAddr(invalidBytes)
    if res.isOk:
      error "Expected error for invalid address length, but conversion succeeded"
      fail()

  test "invalid_ip_address_format":
    let res = multiAddrToBytes(
      "/ip4/127.0.0/tcp/4242/p2p/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC"
    )
    if res.isOk:
      error "Expected error for invalid IP address format, but conversion succeeded"
      fail()

  test "invalid_ip_address_part":
    let res = multiAddrToBytes(
      "/ip4/127.0.0.256/tcp/4242/p2p/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC"
    )
    if res.isOk:
      error "Expected error for invalid IP address part, but conversion succeeded"
      fail()

  test "invalid_base58_encoding":
    let res = multiAddrToBytes(
      "/ip4/127.0.0.1/tcp/4242/p2p/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgV!"
    )
    if res.isOk:
      error "Expected error for invalid Base58 encoding, but conversion succeeded"
      fail()

  test "invalid_multiaddress_format":
    let res = multiAddrToBytes("/ip4/127.0.0.1/tcp/4242")
    if res.isOk:
      error "Expected error for invalid multiaddress format, but conversion succeeded"
      fail()

  test "invalid_port_number":
    let res = multiAddrToBytes(
      "/ip4/127.0.0.1/tcp/65536/p2p/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC"
    )
    if res.isOk:
      error "Expected error for invalid port number, but conversion succeeded"
      fail()

  test "invalid_ip_version":
    let res = multiAddrToBytes(
      "/ip5/127.0.0.1/tcp/4242/p2p/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC"
    )
    if res.isOk:
      error "Expected error for invalid IP version, but conversion succeeded"
      fail()

  test "invalid_ipv6_address":
    let res = multiAddrToBytes(
      "/ip6/invalid::address/tcp/4242/p2p/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC"
    )
    if res.isOk:
      error "Expected error for invalid IPv6 address, but conversion succeeded"
      fail()

  test "bytes_to_uint16_conversion":
    let res = bytesToUInt16([0x12'u8, 0x34'u8])
    if res.isErr:
      error "Bytes to uint16 conversion failed", err = res.error
      fail()
    if res.get() != 0x1234'u16:
      error "Incorrect uint16 conversion", expected = 0x1234'u16, actual = res.get()
      fail()

  test "uint16_to_bytes_conversion":
    let value: uint16 = 0x1234
    let bytes = uint16ToBytes(value)
    if bytes != @[byte 0x12, 0x34]:
      error "Incorrect uint16 to bytes conversion",
        expected = @[byte 0x12, 0x34], actual = bytes
      fail()

  test "bytes_to_uint32_conversion":
    let res = bytesToUInt32([0x12'u8, 0x34'u8, 0x56'u8, 0x78'u8])
    if res.isErr:
      error "Bytes to uint32 conversion failed", err = res.error
      fail()
    if res.get() != 0x12345678'u32:
      error "Incorrect uint32 conversion", expected = 0x12345678'u32, actual = res.get()
      fail()

  test "uint32_to_bytes_conversion":
    let value: uint32 = 0x12345678
    let bytes = uint32ToBytes(value)
    if bytes != @[byte 0x12, 0x34, 0x56, 0x78]:
      error "Incorrect uint32 to bytes conversion",
        expected = @[byte 0x12, 0x34, 0x56, 0x78], actual = bytes
      fail()

  test "uint16_bytes_roundtrip":
    let original: uint16 = 0xABCD'u16
    let bytes = uint16ToBytes(original)
    let roundtripRes = bytesToUInt16(bytes)
    if roundtripRes.isErr:
      error "Uint16 bytes roundtrip failed", err = roundtripRes.error
      fail()
    if roundtripRes.get() != original:
      error "Uint16 bytes roundtrip mismatch",
        expected = original, actual = roundtripRes.get()
      fail()

  test "uint32_bytes_roundtrip":
    let original: uint32 = 0x12345678'u32
    let bytes = uint32ToBytes(original)
    let roundtripRes = bytesToUInt32(bytes)
    if roundtripRes.isErr:
      error "Uint32 bytes roundtrip failed", err = roundtripRes.error
      fail()
    if roundtripRes.get() != original:
      error "Uint32 bytes roundtrip mismatch",
        expected = original, actual = roundtripRes.get()
      fail()
