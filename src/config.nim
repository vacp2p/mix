const
  k* = 16 # Security parameter 
  r* = 5 # Maximum path length
  t* = 3 # t.k - combined length of next hop address and delay
  alphaSize* = 32 # Group element
  betaSize* = 208 # (2r+t)k bytes
  gammaSize* = 16 # Output of HMAC-SHA-256, truncated to 16 bytes
  headerSize* = alphaSize + betaSize + gammaSize  # Total header size
  delaySize* = 2 # Delay size
  addrSize* = (t * k) - delaySize # Address size 
  messageSize* = 2141  # Size of the message itself
  payloadSize* = messageSize + k  # Total payload size
  packetSize* = headerSize + payloadSize # Total packet size