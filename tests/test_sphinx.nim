import ../src/config, ../src/curve25519, ../src/serialization
import ../src/sphinx, ../src/tag_manager
import unittest, random

# Helper function to pad/truncate message
proc padMessage(message: openArray[byte], size: int): seq[byte] =
  if message.len >= size:
    return message[0 .. size - 1] # Truncate if larger
  else:
    result = @message
    let paddingLength = size - message.len
    result.add(newSeq[byte](paddingLength)) # Pad with zeros

# Helper function to check if a mix node is the exit in some message path
proc ifExit(
    address: Hop, delay: seq[byte], processedPacket: seq[byte], status: ProcessingStatus
): bool =
  if (address == Hop()) and (delay == @[]) and (status == Success):
    return true
  else:
    return false

# Helper function to create dummy data
proc createDummyData(): (
  Message, seq[FieldElement], seq[FieldElement], seq[seq[byte]], seq[Hop]
) =
  let (privateKey1, publicKey1) = generateKeyPair()
  let (privateKey2, publicKey2) = generateKeyPair()
  let (privateKey3, publicKey3) = generateKeyPair()

  let privateKeys = @[privateKey1, privateKey2, privateKey3]

  let publicKeys = @[publicKey1, publicKey2, publicKey3]

  let delay =
    @[newSeq[byte](delaySize), newSeq[byte](delaySize), newSeq[byte](delaySize)]

  let hops =
    @[
      initHop(newSeq[byte](addrSize)),
      initHop(newSeq[byte](addrSize)),
      initHop(newSeq[byte](addrSize)),
    ]
  let message = initMessage(newSeq[byte](messageSize))
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
    let packet = wrapInSphinxPacket(message, publicKeys, delay, hops)
    assert packet.len == packetSize, "Packet size be exactly " & $packetSize & " bytes"

    let (address1, delay1, processedPacket1, status1) =
      processSphinxPacket(packet, privateKeys[0], tm)
    assert status1 == Success, "Processing status should be Success"
    assert processedPacket1.len == packetSize,
      "Packet size be exactly " & $packetSize & " bytes"
    assert not ifExit(address1, delay1, processedPacket1, status1),
      "Packet processing failed"

    let (address2, delay2, processedPacket2, status2) =
      processSphinxPacket(processedPacket1, privateKeys[1], tm)
    assert status2 == Success, "Processing status should be Success"
    assert processedPacket2.len == packetSize,
      "Packet size be exactly " & $packetSize & " bytes"
    assert not ifExit(address2, delay2, processedPacket2, status2),
      "Packet processing failed"

    let (address3, delay3, processedPacket3, status3) =
      processSphinxPacket(processedPacket2, privateKeys[2], tm)
    assert status3 == Success, "Processing status should be Success"
    assert ifExit(address3, delay3, processedPacket3, status3),
      "Packet processing failed"

    let processedMessage = initMessage(processedPacket3)
    assert processedMessage == message, "Packet processing failed"

  test "sphinx_wrap_empty_public_keys":
    let (message, _, _, delay, _) = createDummyData()
    let packet = wrapInSphinxPacket(message, @[], delay, @[])
    assert packet.len == 0, "Packet should be empty when public keys are empty"

  test "sphinx_process_invalid_mac":
    let (message, privateKeys, publicKeys, delay, hops) = createDummyData()
    let packet = wrapInSphinxPacket(message, publicKeys, delay, hops)
    assert packet.len == packetSize, "Packet size be exactly " & $packetSize & " bytes"

    # Corrupt the MAC for testing
    var tamperedPacket = packet
    tamperedPacket[0] = packet[0] xor 0x01
    let (_, _, _, status) = processSphinxPacket(tamperedPacket, privateKeys[0], tm)
    assert status == InvalidMAC, "Processing status should be InvalidMAC"

  test "sphinx_process_duplicate_tag":
    let (message, privateKeys, publicKeys, delay, hops) = createDummyData()
    let packet = wrapInSphinxPacket(message, publicKeys, delay, hops)
    assert packet.len == packetSize, "Packet size be exactly " & $packetSize & " bytes"

    # Process the packet twice to test duplicate tag handling
    let (_, _, _, status1) = processSphinxPacket(packet, privateKeys[0], tm)
    assert status1 == Success, "Processing status should be Success"
    let (_, _, _, status2) = processSphinxPacket(packet, privateKeys[0], tm)
    assert status2 == Duplicate, "Processing status should be Duplicate"

  test "sphinx_wrap_and_process_message_sizes":
    let messageSizes = @[32, 64, 128, 256, 512]
    for size in messageSizes:
      let (_, privateKeys, publicKeys, delay, hops) = createDummyData()
      var message = newSeq[byte](size)
      randomize()
      for i in 0 ..< size:
        message[i] = byte(rand(256))
      let paddedMessage = padMessage(message, messageSize)
      let packet =
        wrapInSphinxPacket(initMessage(paddedMessage), publicKeys, delay, hops)
      assert packet.len == packetSize,
        "Packet size be exactly " & $packetSize & " bytes for message size " &
          $messageSize

      let (address1, delay1, processedPacket1, status1) =
        processSphinxPacket(packet, privateKeys[0], tm)
      assert status1 == Success, "Processing status should be Success"
      assert processedPacket1.len == packetSize,
        "Packet size be exactly " & $packetSize & " bytes"
      assert not ifExit(address1, delay1, processedPacket1, status1),
        "Packet processing failed"

      let (address2, delay2, processedPacket2, status2) =
        processSphinxPacket(processedPacket1, privateKeys[1], tm)
      assert status2 == Success, "Processing status should be Success"
      assert processedPacket2.len == packetSize,
        "Packet size be exactly " & $packetSize & " bytes"
      assert not ifExit(address2, delay2, processedPacket2, status2),
        "Packet processing failed"

      let (address3, delay3, processedPacket3, status3) =
        processSphinxPacket(processedPacket2, privateKeys[2], tm)
      assert status3 == Success, "Processing status should be Success"
      assert ifExit(address3, delay3, processedPacket3, status3),
        "Packet processing failed"

      assert processedPacket3 == paddedMessage, "Packet processing failed"
