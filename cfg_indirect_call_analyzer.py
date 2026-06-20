# CFG / Indirect Call Analyzer
#
# Attempts to resolve indirect calls by analyzing:
#   - register-based calls
#   - memory dereferenced calls
#   - vtable-like structures
#   - simple function pointer tables
#
# @category Analysis

import re
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import SymbolType


symbolTable = currentProgram.getSymbolTable()


pattern = re.compile(r"CALL.*\[(0x[0-9a-fA-F]+)\].*")

##########################################################################
# INIT
##########################################################################

listing = currentProgram.getListing()

fm = currentProgram.getFunctionManager()
mem = currentProgram.getMemory()


def get_func(addr):
    return fm.getFunctionContaining(addr)


##########################################################################
# STORAGE
##########################################################################

indirect_calls = []


##########################################################################
# DETECTION HELPERS
##########################################################################

def is_call(op):
    return op.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.CALLOTHER, PcodeOp.LOAD)  


def extract_target(op):

    try:
        return op.getInput(0)
    except:
        return None

def extract_target_from_text(instr):
    
    match = re.search(pattern, instr.toString())
    if match:
        try:
            return match.group(1)
        except:
            return None

    return None


##########################################################################
# MAIN SCAN
##########################################################################

print("\n=== INDIRECT CALL ANALYZER ===\n")

instr_iter = listing.getInstructions(True)

while instr_iter.hasNext() and not monitor.isCancelled():

    instr = instr_iter.next()

    if instr.getMnemonicString() != "CALL":
	    continue
    call_addr = instr.getAddress()
    ops = instr.getPcode()
    for op in ops:

        if not is_call(op):
            continue

        resolved_targets = set()
        ##################################################################
        # TODO HEURISTIC 1: indirect call of the form CALL [address]
        ##################################################################
        target = extract_target_from_text(instr)

        try:
            if target is not None:
                addr = currentProgram.getAddressFactory().getAddress(target)
                
                if addr is not None:                    
                    ptrLocation = addr
                    targetAddrVal = getLong(ptrLocation)
                    targetAddr = toAddr(targetAddrVal)
                    func = fm.getFunctionAt(targetAddr)
                    if func is not None:
                        resolved_targets.add(func)
 
                    symbols = symbolTable.getSymbols(addr)
                    for sym in symbols:
                        if sym.getSymbolType() == SymbolType.LABEL:
                            resolved_targets.add(sym)
                            break

        except Exception as ex:
            pass
        ##################################################################
        # TODO: HEURISTIC 2: memory reference (vtable-like)
        ##################################################################
        try:
            target = extract_target(op)
            
            base = target.getAddress()
            

            if base is not None:

                addr = None

                try:
                    addr = base.getAddress()
                except:
                    pass

                if addr is not None:

                    refs = getReferencesTo(addr)

                    for r in refs:

                        f = get_func(r.getFromAddress())

                        if f is not None:
                            resolved_targets.add(f)

        except Exception as ex:
            pass

        ##################################################################
        # STORE RESULT
        ##################################################################

        indirect_calls.append(
            (
                call_addr,
                resolved_targets
            )
        )


##########################################################################
# REPORT
##########################################################################

for addr, targets in indirect_calls:

    print("INDIRECT CALL @ {}".format(addr))
    
    caller = get_func(addr)
    print("  Caller: {}".format(caller))

    if targets:

        print("  Possible targets:")

        for t in targets:
            print("    -> {}".format(t))

    else:
        print("  Targets: UNKNOWN")

    print("")

print("Done.\n")