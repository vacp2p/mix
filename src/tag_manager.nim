import tables, curve25519, locks

type
  TagManager* = ref object
    lock: Lock
    seenTags: Table[FieldElement, bool]

proc initTagManager*(): TagManager =
  new(result)
  result.seenTags = initTable[FieldElement, bool]()
  initLock(result.lock)

proc addTag*(tm: TagManager, tag: FieldElement) {.gcsafe.} =
  withLock tm.lock:
    tm.seenTags[tag] = true

proc isTagSeen*(tm: TagManager, tag: FieldElement): bool {.gcsafe.} =
  withLock tm.lock:
    result = tm.seenTags.contains(tag)

proc removeTag*(tm: TagManager, tag: FieldElement) {.gcsafe.} =
  withLock tm.lock:
    tm.seenTags.del(tag)

proc clearTags*(tm: TagManager) {.gcsafe.} =
  withLock tm.lock:
    tm.seenTags.clear()