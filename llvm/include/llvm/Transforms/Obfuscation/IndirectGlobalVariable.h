#ifndef OBFUSCATION_INDIRECT_GLOBAL_VARIABLE_H
#define OBFUSCATION_INDIRECT_GLOBAL_VARIABLE_H

// Namespace
namespace llvm {
class FunctionPass;
class PassRegistry;
class IPObfuscationContext;
struct ObfuscationOptions;

FunctionPass* createIndirectGlobalVariablePass();
FunctionPass* createIndirectGlobalVariablePass(bool flag, IPObfuscationContext *IPO, ObfuscationOptions *Options);
void initializeIndirectGlobalVariablePass(PassRegistry &Registry);

}

#endif
