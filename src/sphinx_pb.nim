import protobuf_serialization/proto_parser
import protobuf_serialization

# Generate Nim types from the .proto file
import_proto3 "sphinx.proto3"

proc serialize*(packet: SphinxPacket): seq[byte] =
  return Protobuf.encode(packet)

proc deserialize*(encoded: seq[byte]): SphinxPacket =
  return Protobuf.decode(encoded, SphinxPacket)

proc serializeHeader*(header: Header): seq[byte] =
  return Protobuf.encode(header)

proc deserializeHeader*(encoded: seq[byte]): Header =
  return Protobuf.decode(encoded, Header)

proc serializeHop*(hop: Hop): seq[byte] =
  return Protobuf.encode(hop)

proc deserializeHop*(encoded: seq[byte]): Hop =
  return Protobuf.decode(encoded, Hop)

proc serializeRoutingInfo*(routingInfo: RoutingInfo): seq[byte] =
  return Protobuf.encode(routingInfo)

proc deserializeRoutingInfo*(encoded: seq[byte]): RoutingInfo =
  return Protobuf.decode(encoded, RoutingInfo)

proc serializeHeaderInitials*(headerInitials: HeaderInitials): seq[byte] =
  return Protobuf.encode(headerInitials)

proc deserializeHeaderInitials*(encoded: seq[byte]): HeaderInitials =
  return Protobuf.decode(encoded, HeaderInitials)