#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscation/IndirectBranch.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/IPObfuscationContext.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/CryptoUtils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Analysis/CFG.h"

#include <random>

#define DEBUG_TYPE "indbr"

using namespace llvm;
namespace {
struct IndirectBranch : public FunctionPass {
  static char ID;
  bool flag;

  IPObfuscationContext *IPO;
  ObfuscationOptions *Options;
  std::map<BasicBlock *, unsigned> BBNumbering;
  std::vector<BasicBlock *> BBTargets;        //all conditional branch targets
  CryptoUtils RandomEngine;
  IndirectBranch() : FunctionPass(ID) {
    this->flag = false;
    IPO = nullptr;
    this->Options = nullptr;
  }

  IndirectBranch(bool flag, IPObfuscationContext *IPO, ObfuscationOptions *Options) : FunctionPass(ID) {
    this->flag = flag;
    this->IPO = IPO;
    this->Options = Options;
  }

  StringRef getPassName() const override { return {"IndirectBranch"}; }

  void NumberBasicBlock(Function &F) {
    for (auto &BB : F) {
      if (auto *BI = dyn_cast<BranchInst>(BB.getTerminator())) {
        if (BI->isConditional()) {
          unsigned N = BI->getNumSuccessors();
          for (unsigned I = 0; I < N; I++) {
            BasicBlock *Succ = BI->getSuccessor(I);
            if (BBNumbering.count(Succ) == 0) {
              BBTargets.push_back(Succ);
              BBNumbering[Succ] = 0;
            }
          }
        }
      }
    }

    long seed = RandomEngine.get_uint32_t();
    std::default_random_engine e(seed);
    std::shuffle(BBTargets.begin(), BBTargets.end(), e);

    unsigned N = 0;
    for (auto BB:BBTargets) {
      BBNumbering[BB] = N++;
    }
  }

  GlobalVariable *getIndirectTargets(Function &F, ConstantInt *EncKey) {
    std::string GVName(F.getName().str() + "_IndirectBrTargets");
    GlobalVariable *GV = F.getParent()->getNamedGlobal(GVName);
    if (GV)
      return GV;

    // encrypt branch targets
    std::vector<Constant *> Elements;
    for (const auto BB:BBTargets) {
      Constant *CE = ConstantExpr::getBitCast(BlockAddress::get(BB), Type::getInt8PtrTy(F.getContext()));
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
    if (!toObfuscate(flag, &Fn, "indbr")) {
      return false;
    }

    if (Options && Options->skipFunction(Fn.getName())) {
      return false;
    }

    if (Fn.getBasicBlockList().empty() || Fn.hasLinkOnceLinkage() || Fn.getSection() == ".text.startup") {
      return false;
    }

    LLVMContext &Ctx = Fn.getContext();

    // Init member fields
    BBNumbering.clear();
    BBTargets.clear();

    // llvm cannot split critical edge from IndirectBrInst
    SplitAllCriticalEdges(Fn, CriticalEdgeSplittingOptions(nullptr, nullptr));
    NumberBasicBlock(Fn);

    if (BBNumbering.empty()) {
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
    GlobalVariable *DestBBs = getIndirectTargets(Fn, EncKey);

    for (auto &BB : Fn) {
      auto *BI = dyn_cast<BranchInst>(BB.getTerminator());
      if (BI && BI->isConditional()) {
        IRBuilder<> IRB(BI);

        Value *Cond = BI->getCondition();
        Value *Idx;
        Value *TIdx, *FIdx;

        TIdx = ConstantInt::get(Type::getInt32Ty(Ctx), BBNumbering[BI->getSuccessor(0)]);
        FIdx = ConstantInt::get(Type::getInt32Ty(Ctx), BBNumbering[BI->getSuccessor(1)]);
        Idx = IRB.CreateSelect(Cond, TIdx, FIdx);

        Value *GEP = IRB.CreateGEP(DestBBs, {Zero, Idx});
        LoadInst *EncDestAddr = IRB.CreateLoad(GEP, "EncDestAddr");
        // Use IPO context to compute the encryption key
        // X = FuncSecret - EncKey
        Constant *X;
        if (SecretInfo) {
          X = ConstantExpr::getSub(SecretInfo->SecretCI, EncKey);
        } else {
          X = ConstantExpr::getSub(Zero, EncKey);
        }
        // -EncKey = X - FuncSecret
        Value *DecKey = IRB.CreateSub(X, MySecret);
        Value *DestAddr = IRB.CreateGEP(EncDestAddr, DecKey);

        IndirectBrInst *IBI = IndirectBrInst::Create(DestAddr, 2);
        IBI->addDestination(BI->getSuccessor(0));
        IBI->addDestination(BI->getSuccessor(1));
        ReplaceInstWithInst(BI, IBI);
      }
    }

    return true;
  }

};
} // namespace llvm

char IndirectBranch::ID = 0;
FunctionPass *llvm::createIndirectBranchPass() { return new IndirectBranch(); }
FunctionPass *llvm::createIndirectBranchPass(bool flag,
                                             IPObfuscationContext *IPO,
                                             ObfuscationOptions *Options) {
  return new IndirectBranch(flag, IPO, Options);
}
INITIALIZE_PASS(IndirectBranch, "indbr", "Enable IR Indirect Branch Obfuscation", false, false)
