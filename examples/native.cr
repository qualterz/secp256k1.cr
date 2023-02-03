require "./native/*"
require "openssl"

context = create_context

secret_key, public_key, serialized_public_key = create_ec_keys context
another_secret_key, another_public_key, another_serialized_public_key = create_ec_keys context

shared_secret = create_ecdh_shared_secret context, another_public_key, secret_key
another_shared_secret = create_ecdh_shared_secret context, public_key, another_secret_key

message = OpenSSL::Digest.new("SHA256").update("Hello, crypto!").final

puts "SHA256 message hash: #{message.hexstring}"

ecdsa_signature, ecdsa_serialized_signature = create_ecdsa_signature context, message, secret_key
signature_verification_status = verify_ecdsa_signature context, ecdsa_signature, message, public_key

keypair = create_keypair context
public_key_xonly = create_xonly_public_key context, keypair

schnorr_signature = create_schnorr_signature context, message, keypair
signature_verification_status = verify_schnorr_signature context, schnorr_signature, message, public_key_xonly

destroy_context context
