require "../lib_secp256k1"
require "./common"

module Secp256k1
  class Keypair
    @wrapped_context : LibSecp256k1::Secp256k1Context
    @wrapped_keypair : LibSecp256k1::Secp256k1Keypair

    @random : Random

    def initialize(@wrapped_context, @wrapped_keypair, @random)
    end

    def bytes : Bytes
      @wrapped_keypair.data.to_slice
    end

    def secret_key_bytes : Bytes
      Bytes.new(SECRET_KEY_SIZE).tap { |bytes|
        LibSecp256k1.secp256k1_keypair_sec(
          @wrapped_context,
          bytes,
          pointerof(@wrapped_keypair)
        )
      }
    end

    def public_key : PublicKey
      LibSecp256k1.secp256k1_keypair_pub(
        @wrapped_context,
        out public_key_out,
        pointerof(@wrapped_keypair)
      )

      PublicKey.new(@wrapped_context, public_key_out)
    end

    def xonly_public_key : XOnlyPublicKey
      LibSecp256k1.secp256k1_keypair_xonly_pub(
        @wrapped_context,
        out xonly_public_key_out,
        nil,
        pointerof(@wrapped_keypair)
      )

      XOnlyPublicKey.new(@wrapped_context, xonly_public_key_out)
    end
  end

  class Context
    def keypair_create(secret_key : Bytes) : Keypair
      if LibSecp256k1.secp256k1_keypair_create(
           @wrapped_context,
           out keypair_out,
           secret_key
         ) == Result::Wrong.value
        raise Error.new "Secret key is invalid"
      end

      Keypair.new(@wrapped_context, keypair_out, @random)
    end

    def keypair_generate : Keypair
      secret_key = @random.random_bytes(SECRET_KEY_SIZE)

      begin
        return keypair_create secret_key
      rescue
        raise Error.new "Failed to generate keypair"
      end
    end
  end
end
