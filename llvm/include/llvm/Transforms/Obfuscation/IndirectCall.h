#ifndef OBFUSCATION_INDIRECT_CALL_H
#define OBFUSCATION_INDIRECT_CALL_H

// Namespace
namespace llvm {
class FunctionPass;
class PassRegistry;
class IPObfuscationContext;
struct ObfuscationOptions;

FunctionPass* createIndirectCallPass();
FunctionPass* createIndirectCallPass(bool flag, IPObfuscationContext *IPO, ObfuscationOptions *Options);
void initializeIndirectCallPass(PassRegistry &Registry);

}

#endif
