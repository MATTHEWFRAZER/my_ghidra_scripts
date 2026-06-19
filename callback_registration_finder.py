# Callback Registration Finder
#
# Detects kernel callback registrations and extracts:
#   - registration API
#   - callback function pointer
#   - registration site
#
# @category Analysis

from ghidra.program.model.pcode import PcodeOp


##########################################################################
# CALLBACK APIS
##########################################################################

CALLBACK_APIS = set([
    "PsSetCreateProcessNotifyRoutine",
    "PsSetCreateThreadNotifyRoutine",
    "PsSetLoadImageNotifyRoutine",
    "PsSetRemoveCreateProcessNotifyRoutine",
    "CmRegisterCallbackEx",
    "ObRegisterCallbacks",
    "FltRegisterFilter",
    "FltStartFiltering",
    "FwpsCalloutRegister0",
    "FwpmCalloutAdd0",
])


##########################################################################
# INIT
##########################################################################

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()


def get_func(addr):
    return fm.getFunctionContaining(addr)


##########################################################################
# DETECTION
##########################################################################

print("\n=== CALLBACK REGISTRATION FINDER ===\n")

results = []

instr_iter = listing.getInstructions(True)

while instr_iter.hasNext() and not monitor.isCancelled():

    instr = instr_iter.next()

    ops = instr.getPcode()

    for op in ops:

        if op.getOpcode() != PcodeOp.CALL:
            continue

        if op.getNumInputs() == 0:
            continue

        target = op.getInput(0)

        try:
            addr = target.getAddress()
        except:
            continue

        func = get_func(addr)

        if func is None:
            continue

        name = func.getName()

        if name not in CALLBACK_APIS:
            continue

        ##################################################################
        # Attempt to extract arguments (best-effort heuristic)
        ##################################################################

        callback_fn = None

        try:

            # Windows x64: 2nd or 3rd arg often callback pointer
            # We approximate by scanning surrounding instructions

            instr_addr = instr.getAddress()
            instr_obj = listing.getInstructionAt(instr_addr)

            # look backward for MOV into RCX/RDX/R8
            prev = instr_obj

            for i in range(5):

                if prev is None:
                    break

                prev = listing.getInstructionBefore(prev.getAddress())

                if prev is None:
                    break

                text = str(prev)

                if "LEA" in text or "MOV" in text:

                    # crude heuristic: function pointer load
                    if "PTR" in text or "FUN_" in text:

                        callback_fn = text
                        break

        except:
            pass

        results.append(
            (
                name,
                instr.getAddress(),
                callback_fn
            )
        )


##########################################################################
# REPORT
##########################################################################

for api, addr, cb in results:

    print("API: {}".format(api))
    print("  at: {}".format(addr))

    if cb is not None:
        print("  callback (heuristic): {}".format(cb))
    else:
        print("  callback: UNKNOWN")

    print("")

print("Done.\n")