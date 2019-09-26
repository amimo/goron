#include "llvm/IR/Constants.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Obfuscation/IndirectGlobalVariable.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/IPObfuscationContext.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/CryptoUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#define DEBUG_TYPE "indgv"

using namespace llvm;
namespace {
struct IndirectGlobalVariable : public FunctionPass {
  static char ID;
  bool flag;

  IPObfuscationContext *IPO;
  ObfuscationOptions *Options;
  std::map<GlobalVariable *, unsigned> GVNumbering;
  std::vector<GlobalVariable *> GlobalVariables;
  CryptoUtils RandomEngine;
  IndirectGlobalVariable() : FunctionPass(ID) {
    this->flag = false;
    IPO = nullptr;
    this->Options = nullptr;
  }

  IndirectGlobalVariable(bool flag, IPObfuscationContext *IPO, ObfuscationOptions *Options) : FunctionPass(ID) {
    this->flag = flag;
    this->IPO = IPO;
    this->Options = Options;
  }

  StringRef getPassName() const override { return {"IndirectGlobalVariable"}; }

  void NumberGlobalVariable(Function &F) {
    for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
      for (User::op_iterator op = (*I).op_begin(); op != (*I).op_end(); ++op) {
        Value *val = *op;
        if (GlobalVariable *GV = dyn_cast<GlobalVariable>(val)) {
          if (!GV->isThreadLocal() && GVNumbering.count(GV) == 0) {
            GVNumbering[GV] = GlobalVariables.size();
            GlobalVariables.push_back((GlobalVariable *) val);
          }
        }
      }
    }
  }

  GlobalVariable *getIndirectGlobalVariables(Function &F, ConstantInt *EncKey) {
    std::string GVName(F.getName().str() + "_IndirectGVars");
    GlobalVariable *GV = F.getParent()->getNamedGlobal(GVName);
    if (GV)
      return GV;

    std::vector<Constant *> Elements;
    for (auto GVar:GlobalVariables) {
      Constant *CE = ConstantExpr::getBitCast(GVar, Type::getInt8PtrTy(F.getContext()));
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
    if (!toObfuscate(flag, &Fn, "indgv")) {
      return false;
    }

    if (Options && Options->skipFunction(Fn.getName())) {
      return false;
    }

    LLVMContext &Ctx = Fn.getContext();

    GVNumbering.clear();
    GlobalVariables.clear();

    LowerConstantExpr(Fn);
    NumberGlobalVariable(Fn);

    if (GlobalVariables.empty()) {
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
    GlobalVariable *GVars = getIndirectGlobalVariables(Fn, EncKey);

    for (inst_iterator I = inst_begin(Fn), E = inst_end(Fn); I != E; ++I) {
      Instruction *Inst = &*I;
      if (PHINode *PHI = dyn_cast<PHINode>(Inst)) {
        for (unsigned int i = 0; i < PHI->getNumIncomingValues(); ++i) {
          Value *val = PHI->getIncomingValue(i);
          if (GlobalVariable *GV = dyn_cast<GlobalVariable>(val)) {
            if (GVNumbering.count(GV) == 0) {
              continue;
            }

            Instruction *IP = PHI->getIncomingBlock(i)->getTerminator();
            IRBuilder<> IRB(IP);

            Value *Idx = ConstantInt::get(Type::getInt32Ty(Ctx), GVNumbering[GV]);
            Value *GEP = IRB.CreateGEP(GVars, {Zero, Idx});
            LoadInst *EncGVAddr = IRB.CreateLoad(GEP, GV->getName());
            Constant *X;
            if (SecretInfo) {
              X = ConstantExpr::getSub(SecretInfo->SecretCI, EncKey);
            } else {
              X = ConstantExpr::getSub(Zero, EncKey);
            }

            Value *Secret = IRB.CreateSub(X, MySecret);
            Value *GVAddr = IRB.CreateGEP(EncGVAddr, Secret);
            GVAddr = IRB.CreateBitCast(GVAddr, GV->getType());
            GVAddr->setName("IndGV");
            Inst->replaceUsesOfWith(GV, GVAddr);
          }
        }
      } else {
        for (User::op_iterator op = Inst->op_begin(); op != Inst->op_end(); ++op) {
          if (GlobalVariable *GV = dyn_cast<GlobalVariable>(*op)) {
            if (GVNumbering.count(GV) == 0) {
              continue;
            }

            IRBuilder<> IRB(Inst);
            Value *Idx = ConstantInt::get(Type::getInt32Ty(Ctx), GVNumbering[GV]);
            Value *GEP = IRB.CreateGEP(GVars, {Zero, Idx});
            LoadInst *EncGVAddr = IRB.CreateLoad(GEP, GV->getName());
            Constant *X;
            if (SecretInfo) {
              X = ConstantExpr::getSub(SecretInfo->SecretCI, EncKey);
            } else {
              X = ConstantExpr::getSub(Zero, EncKey);
            }

            Value *Secret = IRB.CreateSub(X, MySecret);
            Value *GVAddr = IRB.CreateGEP(EncGVAddr, Secret);
            GVAddr = IRB.CreateBitCast(GVAddr, GV->getType());
            GVAddr->setName("IndGV");
            Inst->replaceUsesOfWith(GV, GVAddr);
          }
        }
      }
    }

      return true;
    }

  };
} // namespace llvm

char IndirectGlobalVariable::ID = 0;
FunctionPass *llvm::createIndirectGlobalVariablePass() { return new IndirectGlobalVariable(); }
FunctionPass *llvm::createIndirectGlobalVariablePass(bool flag,
                                                     IPObfuscationContext *IPO,
                                                     ObfuscationOptions *Options) {
  return new IndirectGlobalVariable(flag, IPO, Options);
}

INITIALIZE_PASS(IndirectGlobalVariable, "indgv", "Enable IR Indirect Global Variable Obfuscation", false, false)
