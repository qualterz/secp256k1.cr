require "../../src/secp256k1"

def randomness(size = 32)
  Random.new.random_bytes(size)
end
