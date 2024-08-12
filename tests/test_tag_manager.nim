import unittest, tag_manager, curve25519, strutils, tables

suite "tag_manager_tests":
    # Setup to initialize the tag manager before running tests
    initTagManager()

    test "add_and_check_tag":
        let tag = generateRandomFieldElement()
        addTag(tag)
        check isTagSeen(tag)
        let nonexistentTag = generateRandomFieldElement()
        check not isTagSeen(nonexistentTag)

    test "remove_tag":
        let tag = generateRandomFieldElement()
        addTag(tag)
        check isTagSeen(tag)
        removeTag(tag)
        check not isTagSeen(tag)

    test "check_tag_presence":
        let tag = generateRandomFieldElement()
        check not isTagSeen(tag)
        addTag(tag)
        check isTagSeen(tag)
        removeTag(tag)
        check not isTagSeen(tag)

    test "handle_multiple_tags":
        let tag1 = generateRandomFieldElement()
        let tag2 = generateRandomFieldElement()
        addTag(tag1)
        addTag(tag2)
        check isTagSeen(tag1)
        check isTagSeen(tag2)
        removeTag(tag1)
        removeTag(tag2)
        check not isTagSeen(tag1)
        check not isTagSeen(tag2)

    # Teardown to clean up after running tests
    clear(seenTags)
