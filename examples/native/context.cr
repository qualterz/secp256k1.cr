require "./shared"

def create_context
  context = LibSecp256k1.secp256k1_context_create(LibSecp256k1::SECP256K1_CONTEXT_NONE)

  if LibSecp256k1.secp256k1_context_randomize(context, randomness) == 0
    abort "Failed to randomize context."
  end

  return context
end

def destroy_context(context)
  LibSecp256k1.secp256k1_context_destroy context
end
