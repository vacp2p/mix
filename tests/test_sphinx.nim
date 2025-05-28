import chronicles, random, results, unittest
import ../mix/[config, curve25519, serialization, sphinx, tag_manager]

# Helper function to pad/truncate message
proc padMessage(message: openArray[byte], size: int): seq[byte] =
  if message.len >= size:
    return message[0 .. size - 1] # Truncate if larger
  else:
    result = @message
    let paddingLength = size - message.len
    result.add(newSeq[byte](paddingLength)) # Pad with zeros

# Helper function to create dummy data
proc createDummyData(): (
  Message, seq[FieldElement], seq[FieldElement], seq[seq[byte]], seq[Hop]
) =
  var keyPairResult = generateKeyPair()
  if keyPairResult.isErr:
    error "Generate key pair error", err = keyPairResult.error
    fail()
  let (privateKey1, publicKey1) = keyPairResult.get()

  keyPairResult = generateKeyPair()
  if keyPairResult.isErr:
    error "Generate key pair error", err = keyPairResult.error
    fail()
  let (privateKey2, publicKey2) = keyPairResult.get()

  keyPairResult = generateKeyPair()
  if keyPairResult.isErr:
    error "Generate key pair error", err = keyPairResult.error
    fail()
  let (privateKey3, publicKey3) = keyPairResult.get()

  let
    privateKeys = @[privateKey1, privateKey2, privateKey3]
    publicKeys = @[publicKey1, publicKey2, publicKey3]

    delay = @[newSeq[byte](delaySize), newSeq[byte](delaySize), newSeq[byte](delaySize)]

    hops =
      @[
        initHop(newSeq[byte](addrSize)),
        initHop(newSeq[byte](addrSize)),
        initHop(newSeq[byte](addrSize)),
      ]

    message = initMessage(newSeq[byte](messageSize))

  return (message, privateKeys, publicKeys, delay, hops)

# Unit tests for sphinx.nim
suite "Sphinx Tests":
  var tm: TagManager

  setup:
    tm = initTagManager()

  teardown:
    clearTags(tm)

  test "sphinx_wrap_and_process":
    let (message, privateKeys, publicKeys, delay, hops) = createDummyData()

    let packetRes = wrapInSphinxPacket(message, publicKeys, delay, hops)
    if packetRes.isErr:
      error "Sphinx wrap error", err = packetRes.error
    let packet = packetRes.get()

    if packet.len != packetSize:
      error "Packet length is not valid",
        pkt_len = $(packet.len), expected_len = $packetSize
      fail()

    let res1 = processSphinxPacket(packet, privateKeys[0], tm)
    if res1.isErr:
      error "Error in Sphinx processing", err = res1.error
      fail()
    let (address1, delay1, processedPacket1, status1) = res1.get()

    if status1 != Intermediary:
      error "Processing status should be Intermediary"
      fail()

    if processedPacket1.len != packetSize:
      error "Packet length is not valid",
        pkt_len = $(processedPacket1.len), expected_len = $packetSize
      fail()

    let res2 = processSphinxPacket(processedPacket1, privateKeys[1], tm)
    if res2.isErr:
      error "Error in Sphinx processing", err = res2.error
      fail()
    let (address2, delay2, processedPacket2, status2) = res2.get()

    if status2 != Intermediary:
      error "Processing status should be Intermediary"
      fail()

    if processedPacket2.len != packetSize:
      error "Packet length is not valid",
        pkt_len = $(processedPacket2.len), expected_len = $packetSize
      fail()

    let res3 = processSphinxPacket(processedPacket2, privateKeys[2], tm)
    if res3.isErr:
      error "Error in Sphinx processing", err = res3.error
      fail()
    let (address3, delay3, processedPacket3, status3) = res3.get()

    if status3 != Exit:
      error "Processing status should be Exit"
      fail()

    let processedMessage = initMessage(processedPacket3)
    if processedMessage != message:
      error "Packet processing failed"
      fail()

  test "sphinx_wrap_empty_public_keys":
    let (message, _, _, delay, _) = createDummyData()

    let packetRes = wrapInSphinxPacket(message, @[], delay, @[])
    if packetRes.isOk:
      error "Expected Sphinx wrap error when public keys are empty, but got success"
      fail()

  test "sphinx_process_invalid_mac":
    let (message, privateKeys, publicKeys, delay, hops) = createDummyData()

    let packetRes = wrapInSphinxPacket(message, publicKeys, delay, hops)
    if packetRes.isErr:
      error "Sphinx wrap error", err = packetRes.error
    let packet = packetRes.get()

    if packet.len != packetSize:
      error "Packet length is not valid",
        pkt_len = $(packet.len), expected_len = $packetSize
      fail()

    # Corrupt the MAC for testing
    var tamperedPacket = packet
    tamperedPacket[0] = packet[0] xor 0x01

    let res = processSphinxPacket(tamperedPacket, privateKeys[0], tm)
    if res.isErr:
      error "Error in Sphinx processing", err = res.error
      fail()
    let (_, _, _, status) = res.get()

    if status != InvalidMAC:
      error "Processing status should be InvalidMAC"
      fail()

  test "sphinx_process_duplicate_tag":
    let (message, privateKeys, publicKeys, delay, hops) = createDummyData()

    let packetRes = wrapInSphinxPacket(message, publicKeys, delay, hops)
    if packetRes.isErr:
      error "Sphinx wrap error", err = packetRes.error
    let packet = packetRes.get()

    if packet.len != packetSize:
      error "Packet length is not valid",
        pkt_len = $(packet.len), expected_len = $packetSize
      fail()

    # Process the packet twice to test duplicate tag handling
    let res1 = processSphinxPacket(packet, privateKeys[0], tm)
    if res1.isErr:
      error "Error in Sphinx processing", err = res1.error
      fail()
    let (_, _, _, status1) = res1.get()

    if status1 != Intermediary:
      error "Processing status should be Intermediary"
      fail()

    let res2 = processSphinxPacket(packet, privateKeys[0], tm)
    if res2.isErr:
      error "Error in Sphinx processing", err = res2.error
      fail()
    let (_, _, _, status2) = res2.get()

    if status2 != Duplicate:
      error "Processing status should be Duplicate"
      fail()

  test "sphinx_wrap_and_process_message_sizes":
    let messageSizes = @[32, 64, 128, 256, 512]
    for size in messageSizes:
      let (_, privateKeys, publicKeys, delay, hops) = createDummyData()
      var message = newSeq[byte](size)
      randomize()
      for i in 0 ..< size:
        message[i] = byte(rand(256))
      let paddedMessage = padMessage(message, messageSize)

      let packetRes =
        wrapInSphinxPacket(initMessage(paddedMessage), publicKeys, delay, hops)
      if packetRes.isErr:
        error "Sphinx wrap error", err = packetRes.error
      let packet = packetRes.get()

      if packet.len != packetSize:
        error "Packet length is not valid",
          pkt_len = $(packet.len), expected_len = $packetSize, msg_len = $messageSize
        fail()

      let res1 = processSphinxPacket(packet, privateKeys[0], tm)
      if res1.isErr:
        error "Error in Sphinx processing", err = res1.error
        fail()
      let (address1, delay1, processedPacket1, status1) = res1.get()

      if status1 != Intermediary:
        error "Processing status should be Intermediary"
        fail()

      if processedPacket1.len != packetSize:
        error "Packet length is not valid",
          pkt_len = $(processedPacket1.len), expected_len = $packetSize
        fail()

      let res2 = processSphinxPacket(processedPacket1, privateKeys[1], tm)
      if res2.isErr:
        error "Error in Sphinx processing", err = res2.error
        fail()
      let (address2, delay2, processedPacket2, status2) = res2.get()

      if status2 != Intermediary:
        error "Processing status should be Intermediary"
        fail()

      if processedPacket2.len != packetSize:
        error "Packet length is not valid",
          pkt_len = $(processedPacket2.len), expected_len = $packetSize
        fail()

      let res3 = processSphinxPacket(processedPacket2, privateKeys[2], tm)
      if res3.isErr:
        error "Error in Sphinx processing", err = res3.error
        fail()
      let (address3, delay3, processedPacket3, status3) = res3.get()

      if status3 != Exit:
        error "Processing status should be Exit"
        fail()

      if processedPacket3 != paddedMessage:
        error "Packet processing failed"
        fail()
