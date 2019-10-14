#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/IPObfuscationContext.h"
#include "llvm/Transforms/Obfuscation/StringEncryption.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/IR/TypeBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/CryptoUtils.h"
#include <map>
#include <iostream>
#include <algorithm>

#define DEBUG_TYPE "string-encryption"

using namespace llvm;
namespace {
struct StringEncryption : public ModulePass {
  static char ID;
  bool flag;

  struct CSPEntry {
    CSPEntry() : ID(0), Offset(0), DecGV(nullptr), DecFunc(nullptr) {}
    unsigned ID;
    unsigned Offset;
    GlobalVariable *DecGV;
    std::vector<uint8_t> Data;
    std::vector<uint8_t> EncKey;
    Function *DecFunc;
  };

  ObfuscationOptions *Options;
  CryptoUtils RandomEngine;
  std::vector<CSPEntry *> ConstantStringPool;
  std::map<GlobalVariable *, CSPEntry *> CSPEntryMap;
  GlobalVariable *EncryptedStringTable;

  StringEncryption() : ModulePass(ID) {
    this->flag = false;
    Options = nullptr;
  }

  StringEncryption(bool flag, IPObfuscationContext *IPO, ObfuscationOptions *Options) : ModulePass(ID) {
    this->flag = flag;
    this->Options = Options;
    initializeStringEncryptionPass(*PassRegistry::getPassRegistry());
  }

  bool doFinalization(Module &) {
    for (CSPEntry *Entry : ConstantStringPool) {
      delete (Entry);
    }
    return false;
  }

  StringRef getPassName() const override { return {"StringEncryption"}; }

  bool runOnModule(Module &M) override;
  bool processConstantStringUse(Function *F);
  Function *buildDecryptFunction(Module *M, const CSPEntry *Entry);
  void getRandomBytes(std::vector<uint8_t> &Bytes, uint32_t MinSize, uint32_t MixSize);
};
} // namespace llvm

char StringEncryption::ID = 0;
bool StringEncryption::runOnModule(Module &M) {
  // phase 1: collect all c strings.
  for (GlobalVariable &GV : M.globals()) {
    if (!GV.isConstant() || !GV.hasInitializer()) {
      continue;
    }

    if (ConstantDataSequential *CDS = dyn_cast<ConstantDataSequential>(GV.getInitializer())) {
      if (CDS->isCString()) {
        CSPEntry *Entry = new CSPEntry();
        StringRef Data = CDS->getRawDataValues();
        Entry->Data.reserve(Data.size());
        for (unsigned i = 0; i < Data.size(); ++i) {
          Entry->Data.push_back(static_cast<uint8_t>(Data[i]));
        }
        Entry->ID = static_cast<unsigned>(ConstantStringPool.size());
        ConstantAggregateZero *ZeroInit = ConstantAggregateZero::get(CDS->getType());
        GlobalVariable *DecGV = new GlobalVariable(M, CDS->getType(), false, GlobalValue::PrivateLinkage,
                                       ZeroInit, "dec" + Twine::utohexstr(Entry->ID) + GV.getName());
        DecGV->setAlignment(GV.getAlignment());
        Entry->DecGV = DecGV;
        ConstantStringPool.push_back(Entry);
        CSPEntryMap[&GV] = Entry;
      }
    }
  }

  // phase 2: encrypt those strings, build corresponding decrypt function
  for (CSPEntry *Entry: ConstantStringPool) {
    getRandomBytes(Entry->EncKey, 16, 32);
    for (unsigned i = 0; i < Entry->Data.size(); ++i) {
      Entry->Data[i] ^= Entry->EncKey[i % Entry->EncKey.size()];
    }
    Entry->DecFunc = buildDecryptFunction(&M, Entry);
  }

  // phase 3: emit the constant string pool
  // | junk bytes | key 1 | encrypted string 1 | junk bytes | key 2 | encrypted string 2 | ...
  std::vector<uint8_t> Data;
  std::vector<uint8_t> JunkBytes;

  JunkBytes.reserve(32);
  for (CSPEntry *Entry: ConstantStringPool) {
    JunkBytes.clear();
    getRandomBytes(JunkBytes, 16, 32);
    Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());
    Entry->Offset = static_cast<unsigned>(Data.size());
    Data.insert(Data.end(), Entry->EncKey.begin(), Entry->EncKey.end());
    Data.insert(Data.end(), Entry->Data.begin(), Entry->Data.end());
  }

  Constant *CDA = ConstantDataArray::get(M.getContext(), ArrayRef<uint8_t>(Data));
  EncryptedStringTable = new GlobalVariable(M, CDA->getType(), true, GlobalValue::PrivateLinkage,
                                            CDA, "EncryptedStringTable");

  // phase 4: decrypt string back at every use, change the plain string use to the decrypted one
  bool Changed = false;
  for (Function &F:M) {
    if (F.isDeclaration())
      continue;
    Changed |= processConstantStringUse(&F);
  }
  return Changed;
}

void StringEncryption::getRandomBytes(std::vector<uint8_t> &Bytes, uint32_t MinSize, uint32_t MaxSize) {
  uint32_t N = RandomEngine.get_uint32_t();
  uint32_t Len;

  assert(MaxSize >= MinSize);

  if (MinSize == MaxSize) {
    Len = MinSize;
  } else {
    Len = MinSize + (N % (MaxSize - MinSize));
  }

  char *Buffer = new char[Len];
  RandomEngine.get_bytes(Buffer, Len);
  for (uint32_t i = 0; i < Len; ++i) {
    Bytes.push_back(static_cast<uint8_t>(Buffer[i]));
  }

  delete[] Buffer;
}

//
//static void goron_decrypt_string(uint8_t *plain_string, const uint8_t *data)
//{
//  const uint8_t *key = data;
//  uint32_t key_size = 1234;
//  uint8_t *es = (uint8_t *) &data[key_size];
//  uint32_t i;
//  for (i = 0;i < 5678;i ++) {
//    plain_string[i] = es[i] ^ key[i % key_size];
//  }
//}

Function *StringEncryption::buildDecryptFunction(Module *M, const StringEncryption::CSPEntry *Entry) {
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> IRB(Ctx);
  FunctionType *FuncTy = TypeBuilder<void(int8_t *, int8_t *), false>::get(Ctx);
  Function *DecFunc =
      Function::Create(FuncTy, GlobalValue::PrivateLinkage, "goron_decrypt_string_" + Twine::utohexstr(Entry->ID), M);

  auto ArgIt = DecFunc->arg_begin();
  Argument *PlainString = ArgIt; // output
  ++ArgIt;
  Argument *Data = ArgIt;       // input

  PlainString->setName("plain_string");
  PlainString->addAttr(Attribute::NoCapture);
  Data->setName("data");
  Data->addAttr(Attribute::NoCapture);
  Data->addAttr(Attribute::ReadOnly);

  BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", DecFunc);
  BasicBlock *LoopBody = BasicBlock::Create(Ctx, "LoopBody", DecFunc);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", DecFunc);

  IRB.SetInsertPoint(Enter);
  ConstantInt *KeySize = ConstantInt::get(Type::getInt32Ty(Ctx), Entry->EncKey.size());
  Value *EncPtr = IRB.CreateInBoundsGEP(Data, KeySize);
  IRB.CreateBr(LoopBody);

  IRB.SetInsertPoint(LoopBody);
  PHINode *LoopCounter = IRB.CreatePHI(IRB.getInt32Ty(), 2);
  LoopCounter->addIncoming(IRB.getInt32(0), Enter);

  Value *EncCharPtr = IRB.CreateInBoundsGEP(EncPtr, LoopCounter);
  Value *EncChar = IRB.CreateLoad(EncCharPtr);
  Value *KeyIdx = IRB.CreateURem(LoopCounter, KeySize);

  Value *KeyCharPtr = IRB.CreateInBoundsGEP(Data, KeyIdx);
  Value *KeyChar = IRB.CreateLoad(KeyCharPtr);

  Value *DecChar = IRB.CreateXor(EncChar, KeyChar);
  Value *DecCharPtr = IRB.CreateInBoundsGEP(PlainString, LoopCounter);
  IRB.CreateStore(DecChar, DecCharPtr);

  Value *NewCounter = IRB.CreateAdd(LoopCounter, IRB.getInt32(1), "", true, true);
  LoopCounter->addIncoming(NewCounter, LoopBody);

  Value *Cond = IRB.CreateICmpEQ(NewCounter, IRB.getInt32(static_cast<uint32_t>(Entry->Data.size())));
  IRB.CreateCondBr(Cond, Exit, LoopBody);

  IRB.SetInsertPoint(Exit);
  IRB.CreateRetVoid();

  return DecFunc;
}

bool StringEncryption::processConstantStringUse(Function *F) {
  if (!toObfuscate(flag, F, "cse")) {
    return false;
  }
  if (Options && Options->skipFunction(F->getName())) {
    return false;
  }
  LowerConstantExpr(*F);
  bool Changed = false;
  for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
    Instruction *Inst = &*I;
    if (PHINode *PHI = dyn_cast<PHINode>(Inst)) {
      for (unsigned int i = 0; i < PHI->getNumIncomingValues(); ++i) {
        if (GlobalVariable *GV = dyn_cast<GlobalVariable>(PHI->getIncomingValue(i))) {
          auto Iter = CSPEntryMap.find(GV);
          if (Iter == CSPEntryMap.end()) {
            continue;
          }
          CSPEntry *Entry = Iter->second;

          Instruction *InsertPoint = PHI->getIncomingBlock(i)->getTerminator();
          IRBuilder<> IRB(InsertPoint);

          Value *OutBuf = IRB.CreateBitCast(Entry->DecGV, IRB.getInt8PtrTy());
          Value *Data = IRB.CreateInBoundsGEP(EncryptedStringTable, {IRB.getInt32(0), IRB.getInt32(Entry->Offset)});
          IRB.CreateCall(Entry->DecFunc, {OutBuf, Data});

          Inst->replaceUsesOfWith(GV, Entry->DecGV);
          Changed = true;
        }
      }
    } else {
      for (User::op_iterator op = Inst->op_begin(); op != Inst->op_end(); ++op) {
        if (GlobalVariable *GV = dyn_cast<GlobalVariable>(*op)) {
          auto Iter = CSPEntryMap.find(GV);
          if (Iter == CSPEntryMap.end()) {
            continue;
          }
          CSPEntry *Entry = Iter->second;

          IRBuilder<> IRB(Inst);

          Value *OutBuf = IRB.CreateBitCast(Entry->DecGV, IRB.getInt8PtrTy());
          Value *Data = IRB.CreateInBoundsGEP(EncryptedStringTable, {IRB.getInt32(0), IRB.getInt32(Entry->Offset)});
          IRB.CreateCall(Entry->DecFunc, {OutBuf, Data});

          Inst->replaceUsesOfWith(GV, Entry->DecGV);
          Changed = true;
        }
      }
    }
  }

  return Changed;
}

ModulePass *llvm::createStringEncryptionPass() { return new StringEncryption(); }
ModulePass *llvm::createStringEncryptionPass(bool flag,
                                             IPObfuscationContext *IPO,
                                             ObfuscationOptions *Options) {
  return new StringEncryption(flag, IPO, Options);
}

INITIALIZE_PASS(StringEncryption, "string-encryption", "Enable IR String Encryption", false, false)
