import tables, curve25519

# Define a global variable for the tag manager
var seenTags*: Table[FieldElement, bool]

# Initialize the tag manager
proc initTagManager*() =
  seenTags = initTable[FieldElement, bool]()

# Add a tag to the seen list
proc addTag*(tag: FieldElement) =
  seenTags[tag] = true

# Check if a tag has been seen
proc isTagSeen*(tag: FieldElement): bool =
  seenTags.contains(tag)

# Remove a tag from the seen list
proc removeTag*(tag: FieldElement) =
  seenTags.del(tag)
