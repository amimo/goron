add_llvm_library(LLVMObfuscation
  CryptoUtils.cpp
  Utils.cpp
  ObfuscationPassManager.cpp
  ObfuscationOptions.cpp
  IPObfuscationContext.cpp
  IndirectBranch.cpp
  DEPENDS
  LLVMLinker
  )

add_dependencies(LLVMObfuscation intrinsics_gen LLVMLinker)
