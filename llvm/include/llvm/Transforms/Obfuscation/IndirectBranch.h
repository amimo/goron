#ifndef OBFUSCATION_INDIRECTBR_H
#define OBFUSCATION_INDIRECTBR_H

// Namespace
namespace llvm {
class FunctionPass;
class PassRegistry;
class IPObfuscationContext;
struct ObfuscationOptions;

FunctionPass* createIndirectBranchPass();
FunctionPass* createIndirectBranchPass(bool flag, IPObfuscationContext *IPO, ObfuscationOptions *Options);
void initializeIndirectBranchPass(PassRegistry &Registry);

}

#endif
