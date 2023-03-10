require "../lib_secp256k1"
require "./common"

module Secp256k1
  class Schnorr
    MESSAGE_SIZE              = 32
    SIGNATURE_SIZE            = 64
    AUXILIARY_RANDOMNESS_SIZE = 32
  end

  class Keypair
    def schnorr_sign(message : Bytes, auxiliary_randomness : Bytes) : Bytes
      Bytes.new(Schnorr::SIGNATURE_SIZE).tap do |signature|
        if LibSecp256k1.secp256k1_schnorrsig_sign32(
             @wrapped_context,
             signature,
             message,
             pointerof(@wrapped_keypair),
             auxiliary_randomness
           ) == Result::Wrong.value
          raise Error.new "Failed to create Schnorr signature"
        end
      end
    end

    def schnorr_sign(message : Bytes) : Bytes
      schnorr_sign message, @random.random_bytes(Schnorr::AUXILIARY_RANDOMNESS_SIZE)
    end

    def schnorr_verify(signature : Bytes, message : Bytes) : Bool
      xonly_public_key.schnorr_verify(signature, message)
    end

    def schnorr_verify(signature : Bytes) : Bool
      xonly_public_key.schnorr_verify(signature)
    end
  end

  class XOnlyPublicKey
    def schnorr_verify(signature : Bytes, message : Bytes) : Bool
      LibSecp256k1.secp256k1_schnorrsig_verify(
        @wrapped_context,
        signature,
        message,
        message.size,
        pointerof(@wrapped_xonly_public_key)
      ) == Result::Correct.value
    end

    def schnorr_verify(signature : Bytes) : Bool
      LibSecp256k1.secp256k1_schnorrsig_verify(
        @wrapped_context,
        signature,
        nil,
        0,
        pointerof(@wrapped_xonly_public_key)
      ) == Result::Correct.value
    end
  end
end
