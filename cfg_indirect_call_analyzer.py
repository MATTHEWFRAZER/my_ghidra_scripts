# CFG / Indirect Call Analyzer
#
# Attempts to resolve indirect calls by analyzing:
#   - register-based calls
#   - memory dereferenced calls
#   - vtable-like structures
#   - simple function pointer tables
#
# @category Analysis

from ghidra.program.model.pcode import PcodeOp


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
    return op.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.CALLOTHER)  


def extract_target(op):
    # For right now we just take the indirect calls that are deferenced addresses
    for x in op.getInputs():
        varnode_type, constant, _ = x.toString().replace("(", "").replace(")","").split(",")
        if varnode_type == "ram":
	        return constant.strip()
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
   
    ops = instr.getPcode()
    for op in ops:

        if not is_call(op):
            continue

        target = extract_target(op)

        if target is None:
            continue

        addr = currentProgram.getAddressFactory().getAddress(target)

        if addr is None:
            continue
        
        call_addr = instr.getAddress()
        ##################################################################
        # INDIRECT CALL DETECTED
        ##################################################################

        func = get_func(addr)

        resolved_targets = [func]

	    # Attempt to retrieve targets
        ##################################################################
        # TODO HEURISTIC 1: pointer constant
        ##################################################################
        ''''
        try:
            if target.isConstant():

                addr = toAddr(target.getOffset())

                f = get_func(addr)

                if f is not None:
                    resolved_targets.append(f.getName())
		else:
		    pass

        except Exception as ex:
            pass
        '''
        ##################################################################
        # TODO: HEURISTIC 2: memory reference (vtable-like)
        ##################################################################
        ''''
        try:
            if target.getOpcode() == PcodeOp.LOAD:

                base = target.getInput(0)

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
                                resolved_targets.append(f.getName())

        except Exception as ex:
            pass#print(ex)
        '''
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

        for t in set(targets):
            print("    -> {}".format(t))

    else:
        print("  Targets: UNKNOWN")

    print("")

print("Done.\n")