#include "llvm/Transforms/Instrumentation.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetFolder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetLibraryInfo.h"

#include "llvm/Analysis/CallGraph.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"

#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/AliasSetTracker.h"
#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/PredIteratorCache.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetLibraryInfo.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/LoopUtils.h"
#include "llvm/Transforms/Utils/SSAUpdater.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Transforms/FreeSentry/FreeSentry.h"


#include <iostream>
#include <fstream>
#include <set>

using namespace llvm;

#define FSdebug

#define DEBUG_TYPE "FreeSentry"
#define UAFFUNC "registerptr"

STATISTIC(FreeSentryRegptr, "Counts number of register pointer calls that were added before optimization");
STATISTIC(FreeSentryRegptrCall, "Counts number of register pointer calls that were added due to calls");
STATISTIC(FreeSentryRegptrStore, "Counts number of register pointer calls that were added due to stores");
STATISTIC(FreeSentryLoopStat, "Counts number of register pointer calls that were moved due to loop optimization");


static cl::opt<std::string> FSGOFile("fsgout", cl::desc("File to write FreeSentry call analysis too"),
				    cl::init("/tmp/fs-callmodel.raw"), cl::Optional);
static cl::opt<std::string> FSGIFile("fsgin", cl::desc("File to read FreeSentry call model from"),
				    cl::init("/tmp/fs-callmodel.res"), cl::Optional);
static cl::opt<std::string> FSGSFile("fsgsys",  cl::desc("File to read system FreeSentry call model from"),
				    cl::init("/usr/share/freesentry/callmodel.res"), cl::Optional);


namespace {

  typedef std::string String;


  class FreeSentryShared {
    public:
	FreeSentryShared() {
	}

    	void loadcallgraph (String filename) {
      	   std::ifstream infile (filename);
      	   String funcname;
      	   int freecalled;

      	   while (infile >> funcname >> freecalled) {
		freecalls[funcname] = freecalled;
      	   }
        }

	bool callsfree (String funcname) {
	  if (freecalls.find(funcname) == freecalls.end()) {
		  DEBUG(dbgs() << "FSL: can't find function in freecalls, assuming free is called" << "\n");
		return true;
      	  } else {
		bool freecalled = freecalls[funcname];
		// debug
		if (freecalled)
		  DEBUG(dbgs() << "FSL: free is called" << "\n");
		else
		  DEBUG(dbgs() << "FSL: free is not called" << "\n");
		return freecalled;
      	  }
	}

    // if address is taken or GetElementPtr is called on this instruction
    bool HATcheck (Instruction * AI, User *U, Loop * L) {
	if (StoreInst * SI = dyn_cast < StoreInst > (U)) {
	  DEBUG(dbgs() << "HAT: StoreInst " << *SI << "\n");
	  if (AI == SI->getValueOperand ())
	    return true;
	}
	else if (PtrToIntInst * PI = dyn_cast < PtrToIntInst > (U)) {
	  DEBUG(dbgs() << "HAT: PtrToIntInst " << *PI << "\n");
	  if (AI == PI->getOperand (0))
	    return true;
	}

	else if (CallInst * CI = dyn_cast < CallInst > (U)) {
	  DEBUG(dbgs() << "HAT: CallInst " << *U << "\n");
	  Function *F = CI->getCalledFunction ();
	  if (F) {
	    StringRef funcname = F->getName ();
	    if (funcname == UAFFUNC) {
	      return false;
	    }
	  }
	  return true;
	}
	else if (InvokeInst *II = dyn_cast < InvokeInst > (U)) {
	  DEBUG(dbgs() << "HAT: InvokeInst " << *II << "\n");
	  return true;
	}
	else if (SelectInst * SI = dyn_cast < SelectInst > (U)) {
	  DEBUG(dbgs() << "HAT: SelectInst " << *SI << "\n");
	  if (HAT (SI, L))
	    return true;
	}
	else if (PHINode * PN = dyn_cast < PHINode > (U)) {
	  DEBUG(dbgs() << "HAT: PHINode " << *PN << "\n");
	  if (VisitedPHIs.insert (PN))
	    if (HAT (PN, L))
	      return true;
	}
	else if (GetElementPtrInst * GEP =
		 dyn_cast < GetElementPtrInst > (U)) {
	  DEBUG(dbgs() << "HAT: GetElementPtrInst " << *GEP << "\n");
	  if (AI == GEP->getPointerOperand ())
	    return true;
	  else if (HAT (GEP, L))
	    return true;

	}
	else if (BitCastInst * BI = dyn_cast < BitCastInst > (U)) {
	  DEBUG(dbgs() << "HAT: Bitcast " << *BI << "\n");
	  if (HAT (BI, L))
	    return true;
	}
	return false;
    }


    bool HAT (Instruction * AI, Loop *L) {
      for (User * U:AI->users ()) {
	// can't do this, if anyone gets an address that's a problem
	/*   Instruction *UI = cast<Instruction>(U);
	   if (L) {
	      if (L->contains(UI)) {
	    	errs() << "User in loop\n";
	      } else {
		errs() << "User not in loop\n";
		continue;
	      }
	   } */
	if (HATcheck(AI, U, L)) return true;
      }
      return false;
    }

    mutable StringMap < int > freecalls;
    SmallPtrSet < const PHINode *, 16 > VisitedPHIs;


  };


  struct FreeSentry:public FunctionPass, FreeSentryShared {
    static char ID;
      FreeSentry ():FunctionPass (ID) {
      }
      FreeSentry (bool setflag): FunctionPass(ID) {flag = setflag; FreeSentry();}

    bool flag = false;

    using llvm::Pass::doInitialization;
    bool doInitialization (Module & M) override {

	loadcallgraph(FSGIFile);
	loadcallgraph(FSGSFile);

      return false;
    }

    using llvm::Pass::doFinalization;
    bool doFinalization (Module & M) override {
        return false;
    }

    bool runOnFunction (Function & F) override {

      bool freecalled;
      bool changed = false;
      String funcname = F.getName();
      freecalled = callsfree(funcname);

      if (!flag) {
	return false;
      }

      DEBUG(dbgs() << "FS: entering " << funcname << "\n");

      if (freecalled) {
	DEBUG(dbgs() << "FS: This function calls free\n");
      }
      else {
	DEBUG(dbgs() << "FS: This funtion does not call free\n");
      }
      bool prevcall = false;
      for (inst_iterator i = inst_begin (F), e = inst_end (F); i != e; ++i) {
	Instruction *I = &*i;
        if (isa < CallInst > (I)) {

	  DEBUG(dbgs() << "FS: call instruction: " << *I << "\n");
	  CallInst *CI = dyn_cast < CallInst > (I);


	 Function *Func = CI->getCalledFunction ();
	 if (Func) {
	    StringRef funcname = Func->getName ();
	    DEBUG(dbgs() << "FS: Function called: " << funcname << "\n");
	    if (funcname == UAFFUNC) {
		continue;
	    }
	  }

	  Value *Callee = CI->getCalledValue();
	  Type *CalleeType = Callee->getType();
	  if (CalleeType->isPointerTy()) {
	     DEBUG(dbgs() << "FS: called function returns a pointer\n");
	     prevcall = true;
	  }

	} else if (isa < BitCastInst > (I)) {

	  if (prevcall) {
	    prevcall = false;
	    BitCastInst *BCI = dyn_cast < BitCastInst > (I);
	    if (!freecalled) {
		if (!HAT (BCI, NULL)) {
		  DEBUG(dbgs() <<
		    "FS: No address taken of value and no calls to free in function, no need to register this particular pointer\n");
		  continue;
		}
	    }


	    Module *M = F.getParent ();
	    Constant *regptr_def = M->getOrInsertFunction (UAFFUNC,
							   Type::getVoidTy
							   (M->getContext ()),
							   Type::getInt8PtrTy
							   (M->getContext ()),
							   NULL);
	    Function *regptr = cast < Function > (regptr_def);
	    regptr->setCallingConv (CallingConv::C);


	    std::vector < Value * >Args;
	    DEBUG(dbgs() <<
		    "FS (call): adding registerptr for" << *I << "\n");

	    Value *Idx[1];
	    Idx[0] = Constant::getNullValue(Type::getInt32Ty(M->getContext()));
	    GetElementPtrInst *GEP = GetElementPtrInst::Create(I, Idx);

	    //GEP->insertAfter(I);
	    DEBUG(dbgs() <<
		    "FS (call): adding GEP:" << *GEP << "\n");

	    CastInst *cast =
	      CastInst::CreatePointerCast (GEP,
					   Type::getInt8PtrTy (M->getContext
							       ()));

	    //cast->insertAfter (GEP);
	    DEBUG(dbgs() <<
		    "FS (call): adding cast:" << *cast << "\n");

	    Args.push_back ((Value *) cast);

	    CallInst *regptr_call = CallInst::Create (regptr, Args, "");
	    //regptr_call->insertAfter (cast);
	    DEBUG(dbgs() <<
		    "FS (call): adding regptr:" << *regptr_call << "\n");


	    FreeSentryRegptrCall++;
	    FreeSentryRegptr++;
	    changed = true;
	  }

	} else if (isa < StoreInst > (I)) {
	  prevcall = false;
	  DEBUG(dbgs() << "FS: Store instruction: " << *I << "\n");
	  StoreInst *SI = dyn_cast < StoreInst > (I);
	  DEBUG(dbgs() << "FS: Pointer operand: " << *SI->getPointerOperand () << "\n");
	  DEBUG(dbgs() << "FS: Pointer type: " << *SI->
	    getPointerOperand ()->getType () << " (is pointer: " << SI->
	    getPointerOperand ()->getType ()->isPointerTy () << ")\n");
	  DEBUG(dbgs() << "FS: Value operand: " << *SI->getValueOperand () << "\n");
	  DEBUG(dbgs() << "FS: Value type: " << *SI->
	    getValueOperand ()->getType () << " (is pointer: " << SI->
	    getValueOperand ()->getType ()->isPointerTy () << ")\n");

	  Value *valop = SI->getValueOperand ();

	  if (SI->getValueOperand ()->getType ()->isPointerTy ()) {
	    if (isa < GetElementPtrInst > (valop)) {
	      DEBUG(dbgs() << "FS: Value is a getelptrinst\n");
	      GetElementPtrInst *GI = dyn_cast < GetElementPtrInst > (valop);
	      DEBUG(dbgs() << "FS: Getelptr, pointer: " <<
		*GI->getPointerOperand() << "\n");
	      if (isa < LoadInst > (GI->getPointerOperand ())) {
		LoadInst *LI =
		  dyn_cast < LoadInst > (GI->getPointerOperand ());
		DEBUG(dbgs() << "FS: Found loadinst: " <<
		  *LI->getPointerOperand () << "\n");
		if (SI->getPointerOperand () == LI->getPointerOperand ()) {
		  DEBUG(dbgs() <<
		    "FS: Pointer loaded, added to and then stored again, ignore\n");
		  continue;
		}
	      }
	    }

	    if (!freecalled) {
	      if (isa < Instruction > (valop)) {
		Instruction *AI = dyn_cast < Instruction > (valop);
		if (!HAT (AI, NULL)) {
		  DEBUG(dbgs() <<
		    "FS: No address taken of value and no calls to free in function, no need to register this particular pointer\n");
		  continue;
		}
	      }
	    }

	    Module *M = F.getParent ();
	    Constant *regptr_def = M->getOrInsertFunction (UAFFUNC,
							   Type::getVoidTy
							   (M->getContext ()),
							   Type::getInt8PtrTy
							   (M->getContext ()),
							   NULL);
	    Function *regptr = cast < Function > (regptr_def);
	    regptr->setCallingConv (CallingConv::C);


	    std::vector < Value * >Args;
	    CastInst *cast =
	      CastInst::CreatePointerCast (SI->getPointerOperand (),
					   Type::getInt8PtrTy (M->getContext
							       ()));
	    DEBUG(dbgs() <<
		    "FS: adding registerptr for" << *SI->getPointerOperand() << "\n");
	    cast->insertAfter (I);

	    Args.push_back ((Value *) cast);


	    CallInst *regptr_call = CallInst::Create (regptr, Args, "");
	    regptr_call->insertAfter (cast);

	    FreeSentryRegptrStore++;
	    FreeSentryRegptr++;

	    changed = true;
	  }
	} else {
	     prevcall = false;
	}
      }
      return changed;
    }

    void getAnalysisUsage (AnalysisUsage & AU) const override {
      AU.setPreservesAll ();
//      AU.addRequiredID(DemoteRegisterToMemoryID);
//      AU.addRequiredID
    }


  };



  struct FreeSentryLoop:public LoopPass, FreeSentryShared {
    static char ID;		// Pass identification, replacement for typeid
      FreeSentryLoop ():LoopPass (ID) {
	initializeFreeSentryLoopPass(*PassRegistry::getPassRegistry());
      }
      FreeSentryLoop (bool setflag): LoopPass(ID) {flag = setflag; FreeSentryLoop();}

    LoopInfo *LI;
    DominatorTree *DT;
    bool flag = false;


    using llvm::Pass::doInitialization;
    bool doInitialization (Loop * L, LPPassManager & LPM) override {
      DEBUG(dbgs() << "FSL: Loop init: << " << FSGIFile << "\n");
	loadcallgraph(FSGIFile);
	loadcallgraph(FSGSFile);
      return false;
    }

    using llvm::Pass::doFinalization;
    bool doFinalization() override {
	return false;
    }

    void loopcallcheck (Loop * L, bool * lcallsfree, bool * lcallsregptr) {
      for (Loop::block_iterator I = L->block_begin (), E = L->block_end ();
	   I != E; ++I) {
	BasicBlock *BB = *I;
	if (LI->getLoopFor (BB) == L) {
	  for (BasicBlock::iterator I = BB->begin (), E = BB->end ();
	       (I != E); ++I) {
	    Instruction *inst = &*I;
	    if (isa < CallInst > (inst)) {
	      DEBUG(dbgs() << "FSL: Found call instruction: " << *inst << "\n");
	      CallInst *CI = dyn_cast < CallInst > (inst);
	      Function *F = CI->getCalledFunction ();
	      if (F) {
		StringRef funcname = F->getName ();
		DEBUG(dbgs() << "FSL: Function called: " << funcname << "\n");
		if (funcname == UAFFUNC) {
		  *lcallsregptr = true;
		} else if (callsfree(funcname)) {
		  *lcallsfree = true;
		}
	      }
	      else {		// indirect call, assume it calls free
		*lcallsfree = true;
	      }
	    }
	  }
	}
      }
    }

    // based on LICM

    bool runOnLoop (Loop * L, LPPassManager & LPM) override {
      bool freecall = false;
      bool regptrcall = false;
      bool changed = false;

      BasicBlock *Header = L->getHeader();
      Function *F = Header->getParent();

      if (!(F->hasFnAttribute(Attribute::FreeSentry) || flag)) {
	return false;
      }

      if (F->hasFnAttribute(Attribute::NoFreeSentry))
	return false;

      DEBUG(dbgs() << "FSL: Running on loop\n");

      LI = &getAnalysis < LoopInfo > ();
      DT = &getAnalysis<DominatorTreeWrapperPass>().getDomTree();

      for (Loop::iterator LoopItr = L->begin (), LoopItrE = L->end ();
	   LoopItr != LoopItrE; ++LoopItr) {
	Loop *InnerL = *LoopItr;
	DEBUG(dbgs() << "FSL: Inner loop:" << *InnerL << "\n");
	loopcallcheck (InnerL, &freecall, &regptrcall);
      }
      loopcallcheck (L, &freecall, &regptrcall);

      if (freecall) {
	DEBUG(dbgs() << "FSL: Function in loop calls free\n");
	return false;
      }
      if (!regptrcall) {
	DEBUG(dbgs() << "FSL: Regptr is not called in loop\n");
	return false;
      }

      SmallVector < Instruction *, 8 > InstToDelete;

      for (Loop::block_iterator I = L->block_begin (), E = L->block_end ();
	   I != E; ++I) {
	BasicBlock *BB = *I;
	if (LI->getLoopFor (BB) == L) {
	  for (BasicBlock::iterator I = BB->begin (), E = BB->end ();
	       (I != E); ++I) {
	    Instruction *inst = &*I;
	    if (isa < CallInst > (inst)) {
	      CallInst *CI = dyn_cast < CallInst > (inst);
	      Function *F = CI->getCalledFunction ();
	      if (F) {
		StringRef funcname = F->getName ();
		DEBUG(dbgs() << "FSL: Function called: " << funcname << "\n");
		if (funcname == UAFFUNC) {
		  if (CastInst * cast =
		      dyn_cast < CastInst > (CI->getArgOperand (0))) {
		    Value *arg = cast->getOperand (0);
		    DEBUG(dbgs() << "FSL: Arg: " << *arg << "\n");
		    if (Instruction * AI = dyn_cast < Instruction > (arg)) {
		      if (HAT (AI, L)) {
			DEBUG(dbgs() << "FSL: Address taken: " << "\n");
			continue;
		      }

		      if (GetElementPtrInst * GEP =
			  dyn_cast < GetElementPtrInst > (AI)) {
			DEBUG(dbgs() << "FSL: GEP instruction:" << GEP << "\n");
			continue;
		      }
		      DEBUG(dbgs() << "FSL: checking domination\n");
		      // no address taken and not a GEP instruction
		      // move outside of loop
		      BasicBlock *EXBB = L->getExitBlock ();

		      SmallVector<BasicBlock*, 8> ExitBlocks;
  		      L->getExitBlocks(ExitBlocks);

		      bool dominates = true;

 		      for (unsigned i = 0, e = ExitBlocks.size(); i != e; ++i) {
    			if (!DT->dominates(AI->getParent(), ExitBlocks[i])) {
				DEBUG(dbgs() << "Does not dominate exit: " << *arg << "\n");
				dominates = false;
			}
		      }


		      if (dominates && EXBB) {
			Instruction *EXBBI = &EXBB->front ();
			DEBUG(dbgs() << "Exit BB: " << *EXBB << "\n");
			DEBUG(dbgs() << "Exit instruction: " << *EXBBI << "\n");
			DEBUG(dbgs() << "inst: " << *CI << "\n");
			DEBUG(dbgs() << "end: " << *BB->getTerminator () << "\n");
			DEBUG(dbgs() << "term: " << CI->isTerminator () << "\n");
			Function *F = BB->getParent ();
			Module *M = F->getParent ();
			Constant *regptr_def =
			  M->getOrInsertFunction (UAFFUNC,
						  Type::getVoidTy
						  (M->getContext ()),
						  Type::getInt8PtrTy
						  (M->getContext ()),
						  NULL);
			Function *regptr = dyn_cast < Function > (regptr_def);
			regptr->setCallingConv (CallingConv::C);

			std::vector < Value * >Args;
			CastInst *newcast = CastInst::CreatePointerCast (arg,
									 Type::
									 getInt8PtrTy
									 (M->getContext
									  ()));
			newcast->insertBefore (EXBBI);

			Args.push_back ((Value *) newcast);

			CallInst *regptr_call =
			  CallInst::Create (regptr, Args,
					    "");
			regptr_call->insertAfter (newcast);

			InstToDelete.push_back (CI);

	    		FreeSentryLoopStat++;
			changed = true;

		      }
		    }
		  }

		}
	      }
	    }
	  }
	}
      }

      while (!InstToDelete.empty ()) {
	Instruction *del = InstToDelete.pop_back_val ();
	DEBUG(dbgs() << "FSL: deleting:" << del << "\n");
	del->eraseFromParent ();
	changed = true;
      }

      return changed;
    }

    void getAnalysisUsage (AnalysisUsage & AU) const override {
      AU.setPreservesCFG ();
      AU.addRequired < DominatorTreeWrapperPass > ();
      AU.addRequired < LoopInfo > ();
      AU.addRequiredID (LoopSimplifyID);
      AU.addPreservedID (LoopSimplifyID);
      AU.addRequiredID (LCSSAID);
      AU.addPreservedID (LCSSAID);
      AU.addRequired < AliasAnalysis > ();
      AU.addPreserved < AliasAnalysis > ();
      AU.addPreserved < ScalarEvolution > ();
      AU.addRequired < TargetLibraryInfo > ();
      AU.addRequired <FreeSentry> ();
    }



  };


  typedef std::set < String > FSSet;
  typedef std::ofstream ofstream;

  struct FSGraph:public FunctionPass {
    static char ID;
      FSGraph ():FunctionPass (ID) {}
      FSGraph (bool setflag): FunctionPass(ID) {flag = setflag; FSGraph();}

    bool flag = false;
    FSSet *getOrInsertFunction (const Function * F) {
      FSSet & fcalls = FCallMap[F->getName ()];

      return &fcalls;
    }

    bool doInitialization (Module & M) {
      String ErrInfo = "";
      String filename = FSGOFile;
      outfile =
	new raw_fd_ostream (filename.c_str (), ErrInfo, sys::fs::F_Append);
      return false;
    }


    void addToCallGraph (Function * F) {
      FSSet *fcalls = getOrInsertFunction (F);

      for (Function::iterator BB = F->begin (), BBE = F->end ();
	   BB != BBE; ++BB)
	for (BasicBlock::iterator II = BB->begin (), IE = BB->end ();
	     II != IE; ++II) {
	  CallSite CS (cast < Value > (II));
	  if (CS) {
	    const Function *Callee = CS.getCalledFunction ();
	    if (!Callee) {
	      DEBUG(dbgs() << "FSG: Indirect call");
	    }
	    else if (!Callee->isIntrinsic ()) {
	      fcalls->insert (Callee->getName ());
	    }
	  }
	}
    }

    void dumpFunction (Function * F) {

      FSSet *fcalls = getOrInsertFunction (F);
      *outfile << F->getName () << ": ";
      for (FSSet::iterator I = fcalls->begin (), IE = fcalls->end ();
	   I != IE; ++I) {
	String func = *I;
	*outfile << func << " ";
      }
      *outfile << "\n";
    }


    bool runOnFunction (Function & F) override {

      if (!(F.hasFnAttribute(Attribute::FreeSentry) || flag)) {
	return false;
      }

      if (F.hasFnAttribute(Attribute::NoFreeSentry))
	return false;

      DEBUG(dbgs() << "FSG: " << F.getName () << "\n");

      addToCallGraph (&F);

      dumpFunction (&F);

      return false;
    }


    mutable StringMap < FSSet > FCallMap;
    raw_fd_ostream *outfile;

    // We don't modify the program, so we preserve all analyses.
    void getAnalysisUsage (AnalysisUsage & AU) const override {
      AU.setPreservesAll ();
    }
  };

}

char FreeSentry::ID = 0;
char FreeSentryLoop::ID = 0;
char FSGraph::ID = 0;


static RegisterPass <FreeSentry> X("FreeSentry", "UAF Protection");
static RegisterPass <FSGraph> Z("FSGraph", "FreeSentry Call Graph");

//static RegisterPass <FreeSentryLoop> Y("FreeSentryLoop", "UAF Protection Loop optimization");
INITIALIZE_PASS_BEGIN(FreeSentryLoop, "FreeSentryLoop", "UAF Protection Loop optimization", false, false)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(LoopInfo)
INITIALIZE_PASS_DEPENDENCY(LoopSimplify)
INITIALIZE_PASS_DEPENDENCY(LCSSA)
INITIALIZE_PASS_DEPENDENCY(ScalarEvolution)
INITIALIZE_PASS_DEPENDENCY(TargetLibraryInfo)
INITIALIZE_AG_DEPENDENCY(AliasAnalysis)
INITIALIZE_PASS_END(FreeSentryLoop, "FreeSentryLoop", "UAF Protection Loop optimization", false, false)


Pass *llvm::createFreeSentry() {
  return new FreeSentry();
}

Pass *llvm::createFreeSentry(bool flag) {
  return new FreeSentry(flag);
}

Pass *llvm::createFreeSentryLoop() {
  return new FreeSentryLoop();
}

Pass *llvm::createFreeSentryLoop(bool flag) {
  return new FreeSentryLoop(flag);
}

Pass *llvm::createFSGraph() {
  return new FSGraph();
}

Pass *llvm::createFSGraph(bool flag) {
  return new FSGraph(flag);
}
