import ../src/config, ../src/curve25519, ../src/serialization
import ../src/sphinx, ../src/tag_manager
import unittest # sphinx, crypto

# Helper function to check if a mix node is the exit in some message path
proc ifExit(address: Hop, delay: seq[byte], processedPacket: seq[byte], status: ProcessingStatus): bool =
  if (address == Hop()) and (delay == @[]) and (processedPacket == @[]) and (status == Success):
    return true
  else:
    return false

# Helper function to create dummy data
proc createDummyData(): (Message, seq[FieldElement], seq[FieldElement], seq[byte], seq[Hop]) =
  let (privateKey1, publicKey1) = generateKeyPair()
  let (privateKey2, publicKey2) = generateKeyPair()
  let (privateKey3, publicKey3) = generateKeyPair()

  let privateKeys = @[
    privateKey1,
    privateKey2,
    privateKey3
  ]

  let publicKeys = @[
    publicKey1,
    publicKey2,
    publicKey3
  ]

  let delay = newSeq[byte](delaySize)
  let hops = @[
    initHop(newSeq[byte](addrSize)),
    initHop(newSeq[byte](addrSize)),
    initHop(newSeq[byte](addrSize))
  ]
  let message = initMessage(newSeq[byte](messageSize))
  return (message, privateKeys, publicKeys, delay, hops)

# Unit tests for sphinx.nim
suite "Sphinx Tests":
  
  test "sphinx_wrap_and_process":
    # Initialize tag manager
    initTagManager()

    let (message, privateKeys, publicKeys, delay, hops) = createDummyData()
    let packet = wrapInSphinxPacket(message, publicKeys, delay, hops)
    assert packet.len > 0, "Packet should not be empty"
    
    let (address1, delay1, processedPacket1, status1) = processSphinxPacket(packet, privateKeys[0])
    echo "status1: ", status1
    assert status1 == Success, "Processing status should be Success"
    assert processedPacket1.len > 0, "Processed packet should not be empty"
    assert not ifExit(address1, delay1, processedPacket1, status1), "Packet processing failed"

    let (address2, delay2, processedPacket2, status2) = processSphinxPacket(packet, privateKeys[1])
    assert status2 == Success, "Processing status should be Success"
    assert processedPacket2.len > 0, "Processed packet should not be empty"
    assert not ifExit(address2, delay2, processedPacket2, status2), "Packet processing failed"

    let (address3, delay3, processedPacket3, status3) = processSphinxPacket(packet, privateKeys[2])
    assert status3 == Success, "Processing status should be Success"
    assert processedPacket3.len > 0, "Processed packet should not be empty"
    assert ifExit(address3, delay3, processedPacket3, status3), "Packet processing failed"

    let processedMessage = initMessage(processedPacket3)
    assert processedMessage == message, "Packet processing failed"

  #[test "Test processSphinxPacket with duplicate tag":
    # Initialize tag manager and add a tag
    initTagManager()
    let (message, publicKeys, delay, hops, msg) = createDummyData()
    let packet = wrapInSphinxPacket(message, publicKeys, delay, hops, msg)
    let privateKey = generateRandomFieldElement()
    
    # Process the first packet
    let (_, _, _, _) = processSphinxPacket(packet, privateKey)
    
    # Process the same packet again
    let (_, _, _, status) = processSphinxPacket(packet, privateKey)
    assert status == Duplicate, "Processing status should be Duplicate for the same tag"

  test "Test processSphinxPacket with invalid MAC":
    # Initialize tag manager
    initTagManager()
    
    let (message, publicKeys, delay, hops, msg) = createDummyData()
    var packet = wrapInSphinxPacket(message, publicKeys, delay, hops, msg)
    
    # Tamper with the packet to make MAC invalid
    if packet.len > 0:
      packet[0] = not packet[0]  # Flip a bit to alter the packet

    let privateKey = generateRandomFieldElement()
    let (_, _, _, status) = processSphinxPacket(packet, privateKey)
    assert status == InvalidMAC, "Processing status should be InvalidMAC for tampered packet"]#
