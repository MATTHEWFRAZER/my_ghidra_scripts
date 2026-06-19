# Memory Corruption Candidate Finder
#
# Finds functions likely to contain:
#   - buffer overflows
#   - integer overflows
#   - size calculation bugs
#   - allocation/copy mismatches
#
# @category Analysis

from ghidra.program.model.pcode import PcodeOp

##########################################################################
# CONFIG
##########################################################################

COPY_APIS = set([
    "memcpy",
    "memmove",
    "strcpy",
    "strncpy",
    "sprintf",
    "swprintf",
    "RtlCopyMemory",
    "RtlMoveMemory"
])

ALLOC_APIS = set([
    "ExAllocatePool",
    "ExAllocatePool2",
    "ExAllocatePoolWithTag",
    "malloc",
    "HeapAlloc"
])

##########################################################################
# INIT
##########################################################################

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

##########################################################################
# HELPERS
##########################################################################

def get_called_function(instr):

    refs = instr.getReferencesFrom()

    for ref in refs:

        if ref.getReferenceType().isCall():

            f = getFunctionAt(ref.getToAddress())

            if f:
                return f

    return None

##########################################################################
# ANALYSIS
##########################################################################

results = []

print("\n=== MEMORY CORRUPTION CANDIDATE FINDER ===\n")

for func in fm.getFunctions(True):

    score = 0
    findings = []

    alloc_count = 0
    copy_count = 0
    store_count = 0
    multiply_count = 0
    indirect_call_count = 0

    try:

        instr_iter = listing.getInstructions(
            func.getBody(),
            True
        )

        while instr_iter.hasNext():

            instr = instr_iter.next()

            text = str(instr)
            lower = text.lower()

            ##############################################################
            # API analysis
            ##############################################################

            called = get_called_function(instr)

            if called:

                name = called.getName()

                if name in COPY_APIS:

                    copy_count += 1
                    score += 5

                    findings.append(
                        "Copy API: {}".format(name)
                    )

                if name in ALLOC_APIS:

                    alloc_count += 1
                    score += 3

                    findings.append(
                        "Allocation API: {}".format(name)
                    )

            ##############################################################
            # Length / size indicators
            ##############################################################

            if "length" in lower:
                score += 1

            if "size" in lower:
                score += 1

            ##############################################################
            # PCode analysis
            ##############################################################

            for op in instr.getPcode():

                opcode = op.getOpcode()

                if opcode == PcodeOp.STORE:

                    store_count += 1

                elif opcode == PcodeOp.INT_MULT:

                    multiply_count += 1

                elif opcode == PcodeOp.CALLIND:

                    indirect_call_count += 1

        ##############################################################
        # Heuristics
        ##############################################################

        if alloc_count and copy_count:

            score += 10

            findings.append(
                "Allocation followed by copy logic"
            )

        if multiply_count:

            score += multiply_count * 2

            findings.append(
                "{} integer multiplication(s)".format(
                    multiply_count
                )
            )

        if store_count > 20:

            score += 5

            findings.append(
                "High write density ({})".format(
                    store_count
                )
            )

        if indirect_call_count:

            score += indirect_call_count * 3

            findings.append(
                "{} indirect call(s)".format(
                    indirect_call_count
                )
            )

        ##############################################################
        # Driver naming heuristics
        ##############################################################

        lname = func.getName().lower()

        if "ioctl" in lname:

            score += 10

            findings.append(
                "IOCTL path"
            )

        if "dispatch" in lname:

            score += 4

            findings.append(
                "Dispatch path"
            )

        if "parse" in lname:

            score += 6

            findings.append(
                "Parser logic"
            )

        if "decode" in lname:

            score += 6

            findings.append(
                "Decoder logic"
            )

        ##############################################################
        # Save interesting functions
        ##############################################################

        if score >= 10:

            results.append(
                (
                    score,
                    func,
                    findings
                )
            )

    except:
        continue

##########################################################################
# REPORT
##########################################################################

results.sort(
    reverse=True,
    key=lambda x: x[0]
)

for score, func, findings in results:

    print("===================================================")
    print("Function : {}".format(func.getName()))
    print("Address  : {}".format(func.getEntryPoint()))
    print("Risk     : {}".format(score))
    print("")

    seen = set()

    for finding in findings:

        if finding in seen:
            continue

        seen.add(finding)

        print("  - {}".format(finding))

    print("")

print("\nDone.\n")