import unittest, ../src/tag_manager, ../src/curve25519

suite "tag_manager_tests":
  var tm: TagManager

  setup:
    tm = initTagManager()

  teardown:
    clearTags(tm)

  test "add_and_check_tag":
    let tag = generateRandomFieldElement()
    addTag(tm, tag)
    check isTagSeen(tm, tag)
    let nonexistentTag = generateRandomFieldElement()
    check not isTagSeen(tm, nonexistentTag)

  test "remove_tag":
    let tag = generateRandomFieldElement()
    addTag(tm, tag)
    check isTagSeen(tm, tag)
    removeTag(tm, tag)
    check not isTagSeen(tm, tag)

  test "check_tag_presence":
    let tag = generateRandomFieldElement()
    check not isTagSeen(tm, tag)
    addTag(tm, tag)
    check isTagSeen(tm, tag)
    removeTag(tm, tag)
    check not isTagSeen(tm, tag)

  test "handle_multiple_tags":
    let tag1 = generateRandomFieldElement()
    let tag2 = generateRandomFieldElement()
    addTag(tm, tag1)
    addTag(tm, tag2)
    check isTagSeen(tm, tag1)
    check isTagSeen(tm, tag2)
    removeTag(tm, tag1)
    removeTag(tm, tag2)
    check not isTagSeen(tm, tag1)
    check not isTagSeen(tm, tag2)
