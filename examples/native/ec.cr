require "./shared"

def create_ec_keys(context)
  secret_key = loop {
    value = randomness
    verified = LibSecp256k1.secp256k1_ec_seckey_verify context, value
    break value if verified
  }

  puts "Secret key: #{secret_key.hexstring}"

  public_key = LibSecp256k1::Secp256k1Pubkey.new

  if LibSecp256k1.secp256k1_ec_pubkey_create(
       context,
       pointerof(public_key),
       secret_key
     ) == 0
    abort "Failed to create EC public key."
  end

  puts "EC public key raw: #{public_key.data.to_slice.hexstring}"

  compressed_public_key = Bytes.new(33)
  length = compressed_public_key.size.to_u64

  if LibSecp256k1.secp256k1_ec_pubkey_serialize(
       context,
       compressed_public_key,
       pointerof(length),
       pointerof(public_key),
       LibSecp256k1::SECP256K1_EC_COMPRESSED
     ) == 0
    abort "Failed to serialize EC public key."
  end

  puts "EC public key serialized: #{compressed_public_key.hexstring}"

  return {secret_key, public_key, compressed_public_key}
end
