require "../shared"

def create_ec_keys(context)
  secret_key = loop {
    value = randomness
    verified = LibSecp256k1.secp256k1_ec_seckey_verify context, value
    break value if verified
  }

  puts "Secret Key: #{secret_key.hexstring}"

  public_key = LibSecp256k1::Secp256k1Pubkey.new

  unless LibSecp256k1.secp256k1_ec_pubkey_create(
           context,
           pointerof(public_key),
           secret_key
         )
    abort "Failed to create public key"
  end

  puts "Public Key Raw: #{public_key.data.to_slice.hexstring}"

  compressed_public_key = Bytes.new(33)
  length = compressed_public_key.size.to_u64

  unless LibSecp256k1.secp256k1_ec_pubkey_serialize(
           context,
           compressed_public_key,
           pointerof(length),
           pointerof(public_key),
           LibSecp256k1::SECP256K1_EC_COMPRESSED
         )
    abort "Failed to serialize public key"
  end

  puts "Public Key Serialized: #{compressed_public_key.hexstring}"

  return {secret_key, public_key, compressed_public_key}
end