const
  k* = 16 # Security parameter
  MAX_PATH_LEN* = 5
  t* = 3 # t.k - combined length of next hop address and delay
  PATH_LEN* = 3
  alphaSize* = 32 # Group element
  betaSize* = ((MAX_PATH_LEN * (t + 1)) + 1) * k # (r(t+1)+1)k bytes
  gammaSize* = 16 # Output of HMAC-SHA-256, truncated to 16 bytes
  headerSize* = alphaSize + betaSize + gammaSize # Total header size
  delaySize* = 2 # Delay size
  addrSize* = (t * k) - delaySize # Address size
  messageSize* = 2413 - headerSize - k # Size of the message itself
  payloadSize* = messageSize + k # Total payload size
  packetSize* = headerSize + payloadSize # Total packet size
