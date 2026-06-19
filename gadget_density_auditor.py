# Gadget Density Auditor
#
# Defensive hardening analysis.
#
# Identifies functions that contain unusually high
# densities of gadget-like control-flow constructs.
#
# @category Analysis

import re

from ghidra.program.model.pcode import PcodeOp

##########################################################################
# INIT
##########################################################################

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
pattern = re.compile(r"CALL.*(0x[0-9a-fA-F]+).*")

def extract_target_from_op(op):
    
    # For right now we just take the indirect calls that are deferenced addresses
    for x in op.getInputs():
        varnode_type, constant, _ = x.toString().replace("(", "").replace(")","").split(",")
        if varnode_type == "ram":
	        return constant.strip()

    return None

def extract_target_from_text(instr):
    
    match = re.search(pattern, instr.toString())
    if match:
        try:
            return match.group(1)
        except:
            return None

    return None

def calls_guard_function(instr):
    mnemonic = instr.getMnemonicString().upper()
    if mnemonic.startswith("CALL"):
        for op in instr.getPcode():

            target = extract_target_from_text(instr)

            if target is None:
                # try other heuristics
                target = extract_target_from_op(op)
                
                if target is None:
                    continue

            addr = currentProgram.getAddressFactory().getAddress(target)

            if addr is None:
                continue
    
            func = fm.getFunctionContaining(addr)

            if func is None:
                continue
            
            if "guard" in func.toString():
                return True
    return False

##########################################################################
# RESULTS
##########################################################################

results = []

total_rets = 0
total_indirect_calls = 0
total_indirect_jumps = 0

##########################################################################
# ANALYSIS
##########################################################################

print("\n=== GADGET DENSITY AUDITOR ===\n")

for func in fm.getFunctions(True):
    try:

        instr_count = 0
        ret_count = 0
        indirect_calls = 0
        indirect_jumps = 0
        guard_hits = 0

        instr_iter = listing.getInstructions(
            func.getBody(),
            True
        )

        while instr_iter.hasNext():

            instr = instr_iter.next()

            instr_count += 1

            mnemonic = instr.getMnemonicString().upper()

            ##############################################################
            # RETURNS
            ##############################################################

            if mnemonic.startswith("RET"):

                ret_count += 1

            ##############################################################
            # INDIRECT CALLS/JUMPS
            ##############################################################

            for op in instr.getPcode():

                opcode = op.getOpcode()

                if opcode == PcodeOp.CALLIND:

                    indirect_calls += 1

                elif opcode == PcodeOp.BRANCHIND:

                    indirect_jumps += 1

            ##############################################################
            # CFG / Guard Heuristics
            ##############################################################

            text = str(instr).lower()

            if "guard" in text or calls_guard_function(instr):
                guard_hits += 1

            if "security_cookie" in text:
                guard_hits += 1

        ##############################################################
        # SCORE
        ##############################################################

        score = 0

        score += ret_count * 2
        score += indirect_calls * 3
        score += indirect_jumps * 3

        if instr_count <= 10:
            score += 4

        if instr_count <= 5:
            score += 6

        if guard_hits:
            score -= min(guard_hits, 5)

        ##############################################################
        # SAVE
        ##############################################################

        if score > 0:

            results.append(
                (
                    score,
                    func,
                    instr_count,
                    ret_count,
                    indirect_calls,
                    indirect_jumps,
                    guard_hits
                )
            )

        total_rets += ret_count
        total_indirect_calls += indirect_calls
        total_indirect_jumps += indirect_jumps

    except:
        continue

##########################################################################
# REPORT
##########################################################################

results.sort(
    reverse=True,
    key=lambda x: x[0]
)

print("=== TOP FUNCTIONS ===\n")

for (
    score,
    func,
    instr_count,
    ret_count,
    indirect_calls,
    indirect_jumps,
    guard_hits
) in results[:100]:

    print("================================================")
    print("Function         : {}".format(func.getName()))
    print("Address          : {}".format(func.getEntryPoint()))
    print("Instructions     : {}".format(instr_count))
    print("Returns          : {}".format(ret_count))
    print("Indirect Calls   : {}".format(indirect_calls))
    print("Indirect Jumps   : {}".format(indirect_jumps))
    print("Guard Indicators : {}".format(guard_hits))
    print("Gadget Score     : {}".format(score))
    print("")

##########################################################################
# SUMMARY
##########################################################################

print("\n=== MODULE SUMMARY ===\n")

print("Total Returns        : {}".format(total_rets))
print("Total Indirect Calls : {}".format(total_indirect_calls))
print("Total Indirect Jumps : {}".format(total_indirect_jumps))

print("\nDone.\n")