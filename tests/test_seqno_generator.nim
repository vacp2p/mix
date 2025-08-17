import chronicles, sets, unittest
import std/[os, times]
import libp2p/peerid
include ../src/seqno_generator

suite "Sequence Number Generator":
  test "init_seq_no_from_peer_id":
    let
      peerId =
        PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
      seqNo = initSeqNo(peerId)
    if seqNo.counter == 0:
      error "Sequence number initialization failed", counter = seqNo.counter
      fail()

  test "generate_seq_nos_for_different_messages":
    let
      peerId =
        PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
      msg1 = @[byte 1, 2, 3]
      msg2 = @[byte 4, 5, 6]
    var seqNo = initSeqNo(peerId)

    generateSeqNo(seqNo, msg1)
    let seqNo1 = seqNo.counter

    generateSeqNo(seqNo, msg2)
    let seqNo2 = seqNo.counter

    if seqNo1 == seqNo2:
      error "Sequence numbers for different messages should be different",
        seqNo1 = seqNo1, seqNo2 = seqNo2
      fail()

  test "generate_seq_nos_for_same_message":
    let
      peerId =
        PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
      msg = @[byte 1, 2, 3]
    var seqNo = initSeqNo(peerId)

    generateSeqNo(seqNo, msg)
    let seqNo1 = seqNo.counter

    sleep(1000) # Wait for 1 second
    generateSeqNo(seqNo, msg)
    let seqNo2 = seqNo.counter

    if seqNo1 == seqNo2:
      error "Sequence numbers for same message at different times should be different",
        seqNo1 = seqNo1, seqNo2 = seqNo2
      fail()

  test "generate_seq_nos_for_different_peer_ids":
    let
      peerId1 =
        PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
      peerId2 =
        PeerId.init("16Uiu2HAm6WNzw8AssyPscYYi8x1bY5wXyQrGTShRH75bh5dPCjBQ").get()

    var
      seqNo1 = initSeqNo(peerId1)
      seqNo2 = initSeqNo(peerId2)

    if seqNo1.counter == seqNo2.counter:
      error "Sequence numbers for different peer IDs should be different",
        seqNo1 = seqNo1.counter, seqNo2 = seqNo2.counter
      fail()

  test "increment_seq_no":
    let peerId =
      PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
    var seqNo: SeqNo = initSeqNo(peerId)
    let initialCounter = seqNo.counter

    incSeqNo(seqNo)

    if seqNo.counter != initialCounter + 1:
      error "Sequence number must be incremented exactly by one",
        initial = initialCounter, current = seqNo.counter
      fail()

  test "seq_no_wraps_around_at_max_value":
    let peerId =
      PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
    var seqNo = initSeqNo(peerId)
    seqNo.counter = high(uint32) - 1
    let initialEpoch = seqNo.getEpoch()

    if seqNo.counter != high(uint32) - 1:
      error "Sequence number must be max value",
        counter = seqNo.counter, maxval = high(uint32) - 1
      fail()

    # Increment to max value
    incSeqNo(seqNo)
    if seqNo.counter != high(uint32):
      error "Sequence number must be max value", counter = seqNo.counter
      fail()

    if seqNo.getEpoch() != initialEpoch:
      error "Epoch should not change before overflow",
        epoch = seqNo.getEpoch(), expected = initialEpoch
      fail()

    # Now wrap around
    incSeqNo(seqNo)
    if seqNo.counter != 0:
      error "Sequence number must wrap around to 0", counter = seqNo.counter
      fail()

    if seqNo.getEpoch() != initialEpoch + 1:
      error "Epoch must increment on overflow",
        epoch = seqNo.getEpoch(), expected = initialEpoch + 1
      fail()

  test "generate_seq_no_uses_entire_uint32_range":
    let peerId =
      PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
    var
      seqNo = initSeqNo(peerId)
      seenValues = initHashSet[uint32]()

    for i in 0 ..< 10000:
      generateSeqNo(seqNo, @[byte i.uint8])
      seenValues.incl(seqNo.counter)

    if seenValues.len <= 9000:
      error "Sequence numbers must be uniformly distributed",
        uniqueValues = seenValues.len
      fail()

  test "compare_seq_no_same_epoch":
    let peerId =
      PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
    var seqNo1 = initSeqNo(peerId)
    var seqNo2 = initSeqNo(peerId)

    seqNo1.counter = 100
    seqNo2.counter = 200

    if compareSeqNo(seqNo1, seqNo2) != -1:
      error "seqNo1 should be less than seqNo2"
      fail()

    if compareSeqNo(seqNo2, seqNo1) != 1:
      error "seqNo2 should be greater than seqNo1"
      fail()

    seqNo2.counter = 100
    if compareSeqNo(seqNo1, seqNo2) != 0:
      error "Equal sequence numbers should compare as equal"
      fail()

  test "compare_seq_no_different_epochs":
    let peerId =
      PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
    var seqNo1 = initSeqNo(peerId)
    var seqNo2 = initSeqNo(peerId)

    seqNo1.counter = high(uint32)
    seqNo1.epoch = 0
    seqNo2.counter = 0
    seqNo2.epoch = 1

    if compareSeqNo(seqNo1, seqNo2) != -1:
      error "SeqNo from earlier epoch should be less than later epoch"
      fail()

  test "is_next_seq_no_normal_increment":
    let peerId =
      PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
    var current = initSeqNo(peerId)
    var next = initSeqNo(peerId)

    current.counter = 100
    current.epoch = 0
    next.counter = 101
    next.epoch = 0

    if not isNextSeqNo(current, next):
      error "Next sequence number should be recognized as successor"
      fail()

  test "is_next_seq_no_wraparound":
    let peerId =
      PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
    var current = initSeqNo(peerId)
    var next = initSeqNo(peerId)

    current.counter = high(uint32)
    current.epoch = 0
    next.counter = 0
    next.epoch = 1

    if not isNextSeqNo(current, next):
      error "Wraparound sequence number should be recognized as successor"
      fail()

  test "epoch_overflow_handling":
    let peerId =
      PeerId.init("16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC").get()
    var seqNo = initSeqNo(peerId)

    # Simulate multiple wraparounds
    seqNo.counter = high(uint32) - 2
    seqNo.epoch = 5

    for i in 0 .. 5:
      incSeqNo(seqNo)

    if seqNo.epoch != 6:
      error "Epoch should increment after wraparound", epoch = seqNo.epoch, expected = 6
      fail()

    if seqNo.counter != 3:
      error "Counter should be 3 after wraparound",
        counter = seqNo.counter, expected = 3
      fail()
