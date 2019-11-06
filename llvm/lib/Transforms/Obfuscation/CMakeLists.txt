add_llvm_library(LLVMObfuscation
  CryptoUtils.cpp
  Utils.cpp
  ObfuscationPassManager.cpp
  ObfuscationOptions.cpp
  IPObfuscationContext.cpp
  IndirectBranch.cpp
  IndirectCall.cpp
  IndirectGlobalVariable.cpp
  Flattening.cpp
  StringEncryption.cpp
  LegacyLowerSwitch.cpp
  DEPENDS
  LLVMLinker
  )

add_dependencies(LLVMObfuscation intrinsics_gen LLVMLinker)
