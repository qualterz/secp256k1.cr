require "./shared"

def create_schnorr_signature(context, message, keypair)
  signature = Bytes.new(64)

  if LibSecp256k1.secp256k1_schnorrsig_sign32(
       context,
       signature,
       message,
       pointerof(keypair),
       randomness
     ) == 0
    abort "Failed to create Schnorr signature."
  end

  puts "Schnorr signature raw: #{signature.hexstring}"

  return signature
end

def verify_schnorr_signature(context, signature, message, public_key)
  if LibSecp256k1.secp256k1_schnorrsig_verify(
       context,
       signature,
       message,
       32,
       pointerof(public_key)
     ) == 1
    puts "Schnorr signature verified."

    return true
  end

  puts "Schnorr signature verification failed."

  return false
end
