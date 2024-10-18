import unittest
import libp2p/peerid
import std/[os, times], sets
include ../src/seqno_generator

suite "Sequence Number Generator":

  test "init_seq_no_from_peer_id":
    let peerId = PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
    let seqNo = initSeqNo(peerId)
    assert seqNo.counter != 0, "Sequence number must be initialized."

  test "generate_seq_nos_for_different_messages":
    let peerId = PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
    var seqNo = initSeqNo(peerId)
    let msg1 = @[byte 1, 2, 3]
    let msg2 = @[byte 4, 5, 6]
    
    generateSeqNo(seqNo, msg1)
    let seqNo1 = seqNo.counter
    
    generateSeqNo(seqNo, msg2)
    let seqNo2 = seqNo.counter
    
    assert seqNo1 != seqNo2, "Sequence numbers for different messages should be different."

  test "generate_seq_nos_for_same_message":
    let peerId = PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
    var seqNo = initSeqNo(peerId)
    let msg = @[byte 1, 2, 3]
    
    generateSeqNo(seqNo, msg)
    let seqNo1 = seqNo.counter
    
    sleep(1000)  # Wait for 1 second
    generateSeqNo(seqNo, msg)
    let seqNo2 = seqNo.counter
    
    assert seqNo1 != seqNo2, "Sequence numbers for same  message at different times  should be different."

  test "generate_seq_nos_for_different_peer_ids":
    let peerId1 = PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
    let peerId2 = PeerId.init("16Uiu2HAm6WNzw8AssyPscYYi8x1bY5wXyQrGTShRH75bh5dPCjBQ").get()
    
    var seqNo1 = initSeqNo(peerId1)
    var seqNo2 = initSeqNo(peerId2)
    
    assert seqNo1.counter != seqNo2.counter, "Sequence numbers for different peer IDs should be different."

  test "increment_seq_no":
    let peerId = PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
    var seqNo = initSeqNo(peerId)
    let initialCounter = seqNo.counter
    
    incSeqNo(seqNo)
    
    assert seqNo.counter == initialCounter + 1, "Sequence number must be incremented exactly by one."

  test "seq_no_wraps_around_at_max_value":
    let peerId = PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
    var seqNo = initSeqNo(peerId)
    seqNo.counter = high(uint32) - 1
    assert seqNo.counter == high(uint32) - 1, "Sequence number must be max value."
    
    incSeqNo(seqNo)
    assert seqNo.counter == 0, "Sequence number must be wrap around."

  test "generate_seq_no_uses_entire_uint32_range":
    let peerId = PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
    var seqNo = initSeqNo(peerId)
    var seenValues = initHashSet[uint32]()
    
    for i in 0..<10000:
      generateSeqNo(seqNo, @[byte i.uint8])
      seenValues.incl(seqNo.counter)
    
    assert seenValues.len > 9000, "Sequence numbers must be uniformly distributed."