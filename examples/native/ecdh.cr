require "./shared"
require "./ec"

def create_ecdh_shared_secret(context, public_key, secret_key)
  shared_secret = Bytes.new(32)

  if LibSecp256k1.secp256k1_ecdh(
       context,
       shared_secret,
       pointerof(public_key),
       secret_key,
       nil, nil
     ) == 0
    abort "Failed to create ECDH shared secret."
  end

  puts "ECDH shared secret: #{shared_secret.hexstring}"

  return shared_secret
end
