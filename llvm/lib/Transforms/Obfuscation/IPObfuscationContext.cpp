#include "llvm/IR/CallSite.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/Transforms/Obfuscation/IPObfuscationContext.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/CryptoUtils.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Support/Debug.h"

#define DEBUG_TYPE "ipobf"

using namespace llvm;

namespace llvm {

bool IPObfuscationContext::runOnModule(llvm::Module &M) {
  for (auto &F : M) {
    SurveyFunction(F);
  }

  for (auto &F : M) {
    if (F.isDeclaration()) {
      continue;
    }
    IPOInfo *Info = AllocaSecretSlot(F);

    IPOInfoList.push_back(Info);
    IPOInfoMap[&F] = Info;
  }

  std::vector<Function *> NewFuncs;
  for (auto *F : LocalFunctions) {
    Function *NF = InsertSecretArgument(F);
    NewFuncs.push_back(NF);
  }

  for (auto *F: NewFuncs) {
    computeCallSiteSecretArgument(F);
  }

  for (AllocaInst *Slot:DeadSlots) {
    for (Value::use_iterator I = Slot->use_begin(), E = Slot->use_end(); I != E; ++I) {
      if (Instruction *Inst = dyn_cast<Instruction>(I->getUser())) {
        Inst->eraseFromParent();
      }
    }
    Slot->eraseFromParent();
  }
  return true;
}

void IPObfuscationContext::SurveyFunction(Function &F) {
  if (!F.hasLocalLinkage() || F.isDeclaration()) {
    return;
  }

  for (const Use &U : F.uses()) {
    ImmutableCallSite CS(U.getUser());
    if (!CS || !CS.isCallee(&U)) {
      return;
    }

    const Instruction *TheCall = CS.getInstruction();
    if (!TheCall) {
      return;
    }
  }

  LLVM_DEBUG(dbgs() << "Enqueue Local Function  " << F.getName() << "\n");
  LocalFunctions.insert(&F);
}

Function *IPObfuscationContext::InsertSecretArgument(Function *F) {
  FunctionType *FTy = F->getFunctionType();
  std::vector<Type *> Params;

  SmallVector<AttributeSet, 8> ArgAttrVec;
  const AttributeList &PAL = F->getAttributes();

  Params.push_back(Type::getInt32PtrTy(F->getContext()));
  ArgAttrVec.push_back(AttributeSet());

  unsigned i = 0;
  for (Function::arg_iterator I = F->arg_begin(), E = F->arg_end(); I != E;
       ++I, ++i) {
    Params.push_back(I->getType());
    ArgAttrVec.push_back(PAL.getParamAttributes(i));
  }

  // Find out the new return value.
  Type *RetTy = FTy->getReturnType();

  // The existing function return attributes.
  AttributeSet RAttrs = PAL.getRetAttributes();

  // Reconstruct the AttributesList based on the vector we constructed.
  AttributeList NewPAL = AttributeList::get(F->getContext(), PAL.getFnAttributes(), RAttrs, ArgAttrVec);

  // Create the new function type based on the recomputed parameters.
  FunctionType *NFTy = FunctionType::get(RetTy, Params, FTy->isVarArg());

  // Create the new function body and insert it into the module...
  Function *NF = Function::Create(NFTy, F->getLinkage());
  NF->copyAttributesFrom(F);
  NF->setComdat(F->getComdat());
  NF->setAttributes(NewPAL);
  // Insert the new function before the old function, so we won't be processing
  // it again.
  F->getParent()->getFunctionList().insert(F->getIterator(), NF);
  NF->takeName(F);
  NF->setSubprogram(F->getSubprogram());

  SmallVector<Value *, 8> Args;
  while (!F->use_empty()) {
    CallSite CS(F->user_back());
    Instruction *Call = CS.getInstruction();

    ArgAttrVec.clear();
    const AttributeList &CallPAL = CS.getAttributes();

    // Get the Secret Token
    Function *Caller = Call->getParent()->getParent();
    IPOInfo *SecretInfo = IPOInfoMap[Caller];
    Args.push_back(SecretInfo->CalleeSlot);
    ArgAttrVec.push_back(AttributeSet());
    // Declare these outside of the loops, so we can reuse them for the second
    // loop, which loops the varargs.
    CallSite::arg_iterator I = CS.arg_begin();
    unsigned i = 0;
    // Loop over those operands, corresponding to the normal arguments to the
    // original function, and add those that are still alive.
    for (unsigned e = FTy->getNumParams(); i != e; ++I, ++i) {
      Args.push_back(*I);
      AttributeSet Attrs = CallPAL.getParamAttributes(i);
      ArgAttrVec.push_back(Attrs);
    }

    // Push any varargs arguments on the list. Don't forget their attributes.
    for (CallSite::arg_iterator E = CS.arg_end(); I != E; ++I, ++i) {
      Args.push_back(*I);
      ArgAttrVec.push_back(CallPAL.getParamAttributes(i));
    }

    // Reconstruct the AttributesList based on the vector we constructed.
    AttributeList NewCallPAL =
        AttributeList::get(F->getContext(), CallPAL.getFnAttributes(), CallPAL.getRetAttributes(), ArgAttrVec);

    Instruction *New;
    if (InvokeInst *II = dyn_cast<InvokeInst>(Call)) {
      New = InvokeInst::Create(NF, II->getNormalDest(), II->getUnwindDest(),
                               Args, "", Call);
      cast<InvokeInst>(New)->setCallingConv(CS.getCallingConv());
      cast<InvokeInst>(New)->setAttributes(NewCallPAL);
    } else {
      New = CallInst::Create(NF, Args, "", Call);
      cast<CallInst>(New)->setCallingConv(CS.getCallingConv());
      cast<CallInst>(New)->setAttributes(NewCallPAL);
      if (cast<CallInst>(Call)->isTailCall())
        cast<CallInst>(New)->setTailCall();
    }
    New->setDebugLoc(Call->getDebugLoc());

    Args.clear();

    if (!Call->use_empty()) {
      Call->replaceAllUsesWith(New);
      New->takeName(Call);
    }

    // Finally, remove the old call from the program, reducing the use-count of
    // F.
    Call->eraseFromParent();
  }

  NF->getBasicBlockList().splice(NF->begin(), F->getBasicBlockList());

  // Loop over the argument list, transferring uses of the old arguments over to
  // the new arguments, also transferring over the names as well.
  Function::arg_iterator I2 = NF->arg_begin();
  I2->setName("SecretArg");
  ++I2;
  for (Function::arg_iterator I = F->arg_begin(), E = F->arg_end(); I != E;
       ++I) {
    I->replaceAllUsesWith(I2);
    I2->takeName(I);
    ++I2;
  }

  // Load Secret Token from the secret argument
  IntegerType *I32Ty = Type::getInt32Ty(NF->getContext());
  IRBuilder<> IRB(&NF->getEntryBlock().front());
  Value *Ptr = IRB.CreateBitCast(NF->arg_begin(), I32Ty->getPointerTo());
  LoadInst *MySecret = IRB.CreateLoad(Ptr);

  IPOInfo *Info = IPOInfoMap[F];
  Info->SecretLI->eraseFromParent();
  Info->SecretLI = MySecret;
  DeadSlots.push_back(Info->CallerSlot);

  IPOInfoMap[NF] = Info;
  IPOInfoMap.erase(F);

  F->eraseFromParent();

  return NF;
}

// Create StackSlots for Secrets and a LoadInst for caller's secret slot
IPObfuscationContext::IPOInfo *IPObfuscationContext::AllocaSecretSlot(Function &F) {
  IRBuilder<> IRB(&F.getEntryBlock().front());
  IntegerType *I32Ty = Type::getInt32Ty(F.getContext());
  AllocaInst *CallerSlot = IRB.CreateAlloca(I32Ty, nullptr, "CallerSlot");
  CallerSlot->setAlignment(Align(4));
  AllocaInst *CalleeSlot = IRB.CreateAlloca(I32Ty, nullptr, "CalleeSlot");
  CalleeSlot->setAlignment(Align(4));

  CryptoUtils RandomEngine;
  uint32_t V = RandomEngine.get_uint32_t();
  ConstantInt *SecretCI = ConstantInt::get(I32Ty, V, false);
  IRB.CreateStore(SecretCI, CallerSlot);
  LoadInst *MySecret = IRB.CreateLoad(CallerSlot, "MySecret");

  IPOInfo *Info = new IPOInfo(CallerSlot, CalleeSlot, MySecret, SecretCI);
  return Info;
}

char IPObfuscationContext::ID = 0;

bool IPObfuscationContext::doFinalization(Module &) {
  for (auto *Info : IPOInfoList) {
    delete (Info);
  }
  return false;
}

const IPObfuscationContext::IPOInfo *IPObfuscationContext::getIPOInfo(Function *F) {
  return IPOInfoMap[F];
}

// at each callsite, compute the callee's secret argument using the caller's
void IPObfuscationContext::computeCallSiteSecretArgument(Function *F) {
  IPOInfo *CalleeIPOInfo = IPOInfoMap[F];

  for (const Use &U : F->uses()) {
    CallSite CS(U.getUser());
    Instruction *Call = CS.getInstruction();
    IRBuilder<> IRB(Call);

    Function *Caller = Call->getParent()->getParent();
    IPOInfo *CallerIPOInfo = IPOInfoMap[Caller];

    Value *CallerSecret;
    CallerSecret = CallerIPOInfo->SecretLI;

    Constant *X = ConstantExpr::getSub(CallerIPOInfo->SecretCI, CalleeIPOInfo->SecretCI);
    Value *CalleeSecret = IRB.CreateSub(CallerSecret, X);
    IRB.CreateStore(CalleeSecret, CallerIPOInfo->CalleeSlot);
  }
}
}

IPObfuscationContext *llvm::createIPObfuscationContextPass(bool flag) {
  return new IPObfuscationContext(flag);
}

INITIALIZE_PASS(IPObfuscationContext, "ipobf", "IPObfuscationContext", false, false)
