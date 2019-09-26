#ifndef __UTILS_OBF__
#define __UTILS_OBF__

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Utils/Local.h" // For DemoteRegToStack and DemotePHIToStack

using namespace llvm;
bool valueEscapes(Instruction *Inst);
void fixStack(Function *f);
std::string readAnnotate(Function *f);
bool toObfuscate(bool flag, Function *f, std::string attribute);
void LowerConstantExpr(Function &F);

#endif
