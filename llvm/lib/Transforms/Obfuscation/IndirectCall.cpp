#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Obfuscation/IndirectCall.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/IPObfuscationContext.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/CryptoUtils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Analysis/CFG.h"

#include <random>

#define DEBUG_TYPE "icall"

using namespace llvm;
namespace {
struct IndirectCall : public FunctionPass {
  static char ID;
  bool flag;

  IPObfuscationContext *IPO;
  ObfuscationOptions *Options;
  std::map<Function *, unsigned> CalleeNumbering;
  std::vector<CallInst *> CallSites;
  std::vector<Function *> Callees;
  CryptoUtils RandomEngine;
  IndirectCall() : FunctionPass(ID) {
    this->flag = false;
    IPO = nullptr;
    this->Options = nullptr;
  }

  IndirectCall(bool flag, IPObfuscationContext *IPO, ObfuscationOptions *Options) : FunctionPass(ID) {
    this->flag = flag;
    this->IPO = IPO;
    this->Options = Options;
  }

  StringRef getPassName() const override { return {"IndirectCall"}; }

  void NumberCallees(Function &F) {
    for (auto &BB:F) {
      for (auto &I:BB) {
        if (dyn_cast<CallInst>(&I)) {
          CallSite CS(&I);
          Function *Callee = CS.getCalledFunction();
          if (Callee == nullptr) {
            continue;
          }
          if (Callee->isIntrinsic()) {
            continue;
          }
          CallSites.push_back((CallInst *) &I);
          if (CalleeNumbering.count(Callee) == 0) {
            CalleeNumbering[Callee] = Callees.size();
            Callees.push_back(Callee);
          }
        }
      }
    }
  }

  GlobalVariable *getIndirectCallees(Function &F, ConstantInt *EncKey) {
    std::string GVName(F.getName().str() + "_IndirectCallees");
    GlobalVariable *GV = F.getParent()->getNamedGlobal(GVName);
    if (GV)
      return GV;

    // callee's address
    std::vector<Constant *> Elements;
    for (auto Callee:Callees) {
      Constant *CE = ConstantExpr::getBitCast(Callee, Type::getInt8PtrTy(F.getContext()));
      CE = ConstantExpr::getGetElementPtr(Type::getInt8Ty(F.getContext()), CE, EncKey);
      Elements.push_back(CE);
    }

    ArrayType *ATy = ArrayType::get(Type::getInt8PtrTy(F.getContext()), Elements.size());
    Constant *CA = ConstantArray::get(ATy, ArrayRef<Constant *>(Elements));
    GV = new GlobalVariable(*F.getParent(), ATy, false, GlobalValue::LinkageTypes::PrivateLinkage,
                                               CA, GVName);
    appendToCompilerUsed(*F.getParent(), {GV});
    return GV;
  }


  bool runOnFunction(Function &Fn) override {
    if (!toObfuscate(flag, &Fn, "icall")) {
      return false;
    }

    if (Options && Options->skipFunction(Fn.getName())) {
      return false;
    }

    LLVMContext &Ctx = Fn.getContext();

    CalleeNumbering.clear();
    Callees.clear();
    CallSites.clear();

    NumberCallees(Fn);

    if (Callees.empty()) {
      return false;
    }

    uint32_t V = RandomEngine.get_uint32_t() & ~3;
    ConstantInt *EncKey = ConstantInt::get(Type::getInt32Ty(Ctx), V, false);

    const IPObfuscationContext::IPOInfo *SecretInfo = nullptr;
    if (IPO) {
      SecretInfo = IPO->getIPOInfo(&Fn);
    }

    Value *MySecret;
    if (SecretInfo) {
      MySecret = SecretInfo->SecretLI;
    } else {
      MySecret = ConstantInt::get(Type::getInt32Ty(Ctx), 0, true);
    }

    ConstantInt *Zero = ConstantInt::get(Type::getInt32Ty(Ctx), 0);
    GlobalVariable *Targets = getIndirectCallees(Fn, EncKey);

    for (auto CI : CallSites) {
      SmallVector<Value *, 8> Args;
      SmallVector<AttributeSet, 8> ArgAttrVec;

      CallSite CS(CI);

      Instruction *Call = CS.getInstruction();
      Function *Callee = CS.getCalledFunction();
      FunctionType *FTy = CS.getFunctionType();
      IRBuilder<> IRB(Call);

      Args.clear();
      ArgAttrVec.clear();

      Value *Idx = ConstantInt::get(Type::getInt32Ty(Ctx), CalleeNumbering[CS.getCalledFunction()]);
      Value *GEP = IRB.CreateGEP(Targets, {Zero, Idx});
      LoadInst *EncDestAddr = IRB.CreateLoad(GEP, CI->getName());
      Constant *X;
      if (SecretInfo) {
        X = ConstantExpr::getSub(SecretInfo->SecretCI, EncKey);
      } else {
        X = ConstantExpr::getSub(Zero, EncKey);
      }

      const AttributeList &CallPAL = CS.getAttributes();
      CallSite::arg_iterator I = CS.arg_begin();
      unsigned i = 0;

      for (unsigned e = FTy->getNumParams(); i != e; ++I, ++i) {
        Args.push_back(*I);
        AttributeSet Attrs = CallPAL.getParamAttributes(i);
        ArgAttrVec.push_back(Attrs);
      }

      for (CallSite::arg_iterator E = CS.arg_end(); I != E; ++I, ++i) {
        Args.push_back(*I);
        ArgAttrVec.push_back(CallPAL.getParamAttributes(i));
      }

      AttributeList NewCallPAL = AttributeList::get(
          IRB.getContext(), CallPAL.getFnAttributes(), CallPAL.getRetAttributes(), ArgAttrVec);

      Value *Secret = IRB.CreateSub(X, MySecret);
      Value *DestAddr = IRB.CreateGEP(EncDestAddr, Secret);

      Value *FnPtr = IRB.CreateBitCast(DestAddr, FTy->getPointerTo());
      FnPtr->setName("Call_" + Callee->getName());
      CallInst *NewCall = IRB.CreateCall(FTy, FnPtr, Args, Call->getName());
      NewCall->setAttributes(NewCallPAL);
      Call->replaceAllUsesWith(NewCall);
      Call->eraseFromParent();
    }

    return true;
  }

};
} // namespace llvm

char IndirectCall::ID = 0;
FunctionPass *llvm::createIndirectCallPass() { return new IndirectCall(); }
FunctionPass *llvm::createIndirectCallPass(bool flag,
                                             IPObfuscationContext *IPO,
                                             ObfuscationOptions *Options) {
  return new IndirectCall(flag, IPO, Options);
}

INITIALIZE_PASS(IndirectCall, "icall", "Enable IR Indirect Call Obfuscation", false, false)
