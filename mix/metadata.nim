import chronos, sequtils, strutils
import std/[strformat, options]
import json
import stew/endians2
when not defined(metadata):
  static:
    discard error "This file allows security-compromising plain-text. only to be used for development purposes"



import std/json


type MetadataEvent* = enum
  Publish
  Send
  Success
  Exiting
  Received

type MetadataLog* = object 
  event*: MetadataEvent
  myId*: string
  fromId*: string
  toId*: Option[string]
  msgId*: uint64
  # sentTs*: uint64
  # Moment the packet was received on this hop
  entryTs*: uint64
  # Moment the packet was handled/forwarded on this hop
  exitTS*: uint64
  # Any extra metadata added
  extras*: Option[JsonNode]

# piggybacking over the top of sphinx
type MetadataPacket* = object
  # genesisTs*: uint64
  msgId*: uint64


proc logFromPacket*(
  packet: MetadataPacket,
  event: MetadataEvent,
  myId: string,
  fromId: string,
  toId: Option[string],
  # Moment the packet was received on this hop
  entryTs: uint64,
  # Moment the packet was handled/forwarded on this hop
  exitTS: uint64,
  # Any extra metadata added
  extras: Option[JsonNode],
): MetadataLog = 
  MetadataLog(
    event: event,
    myId: myId,
    fromId: fromId,
    toId: toId,
    msgId: packet.msgId,
    # Moment the packet was received on this hop
    entryTs: entryTs, #entryTs,
    # Moment the packet was handled/forwarded on this hop
    exitTS: exitTs, #exitTs,
    # Any extra metadata added
    extras: extras
  )


proc mdSerialize*(metadata: MetadataPacket): seq[byte] =
    var res: seq[byte]
    res.add(toBytesLE(metadata.msgId))
    return res

proc mdDeserialize*(data: seq[byte]): MetadataPacket =
  doAssert(data.len == 16, fmt("only deser length of 16: {data}"))
  let msgid = uint64.fromBytesLE(data[0 ..< 8])
  MetadataPacket( msgId: msgid)

proc leftTruncate(s: string, length: int): string =
  if s.len > length:
    return s[s.len - length ..< s.len]
  else:
    return s

proc `$`*(md: MetadataLog): string = 

  var toIdStr: string
  if md.toId.isSome():
    toIdStr = $(md.toId.get())
  else:
    toIdStr = "None"
 
  var extraStr: string
  if md.extras.isSome():
    extraStr = $(md.extras.get())
  else:
    extraStr = "None" 

  fmt"event: {md.event:<8}|myId: {leftTruncate(md.myId, 6):<6}|fromId: {leftTruncate(md.fromId, 6):<6}|toId: {leftTruncate(toIdStr, 6):<6}|msgId: {md.msgId:<3}|entryTs: {leftTruncate($md.entryTs, 10):<10}| exitTs: {leftTruncate($md.exitTs, 10):<10}| extras: {extraStr}"

proc metaDataLogJson*(md: MetadataLog): JsonNode = 
  return %*{
    "event": md.event,
    "myId": md.myId,
    "fromId": md.fromId,
    "toId": md.toId,
    "msgId": md.msgId,
    "entryTs": md.entryTs,
    "exitTs": md.exitTs,
    "extras": md.extras,
  }

