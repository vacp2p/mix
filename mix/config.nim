const
  k* = 16 # Security parameter
  MAX_PATH_LEN* = 5
  t* = 3 # t.k - combined length of next hop address and delay
  PATH_LEN* = 3
  # Group element
  ALPHA_SIZE* = 32
  # (r(t+1)+1)k bytes
  BETA_SIZE* = ((MAX_PATH_LEN * (t + 1)) + 1) * k
  # Output of HMAC-SHA-256, truncated to 16 bytes
  GAMMA_SIZE* = 16
  HEADER_SIZE* = ALPHA_SIZE + BETA_SIZE + GAMMA_SIZE
  DELAY_SIZE* = 2
  ADDR_SIZE* = (t * k) - DELAY_SIZE
  MSG_SIZE* = 2413 - HEADER_SIZE - k
  PAYLOAD_SIZE* = MSG_SIZE + k
  PACKET_SIZE* = HEADER_SIZE + PAYLOAD_SIZE
