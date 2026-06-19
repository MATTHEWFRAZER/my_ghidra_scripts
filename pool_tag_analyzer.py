# Pool Tag Analyzer
#
# Extracts Windows kernel pool allocations and groups by pool tag.
#
# @category Analysis

from ghidra.program.model.pcode import PcodeOp


##########################################################################
# CONFIG
##########################################################################

ALLOC_FUNCS = set([
    "ExAllocatePool2",
    "ExAllocatePoolWithTag",
])

FREE_FUNCS = set([
    "ExFreePool",
    "ExFreePool2",
])


##########################################################################
# INIT
##########################################################################

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()


def get_func(addr):
    return fm.getFunctionContaining(addr)


##########################################################################
# DATA STRUCTURES
##########################################################################

tag_map = {}   # tag -> list of (func, addr, size)
alloc_sites = {}


##########################################################################
# SCAN
##########################################################################

print("\n=== POOL TAG ANALYZER ===\n")

instr_iter = listing.getInstructions(True)

while instr_iter.hasNext() and not monitor.isCancelled():

    instr = instr_iter.next()

    ops = instr.getPcode()

    for op in ops:

        if op.getOpcode() != PcodeOp.CALL:
            continue

        if op.getNumInputs() < 1:
            continue

        target = op.getInput(0)

        try:
            callee_addr = target.getAddress()
        except:
            continue

        func = get_func(callee_addr)

        if func is None:
            continue

        name = func.getName()

        if name not in ALLOC_FUNCS:
            continue

        ##################################################################
        # Try to extract pool tag argument
        ##################################################################

        tag = None
        size = None

        try:

            # Heuristic: scan previous instructions for constants
            prev = listing.getInstructionBefore(instr)

            for i in range(6):

                if prev is None:
                    break

                text = str(prev)

                # pool tag often appears as immediate like 'ABCD'
                if "0x" in text:

                    parts = text.split("0x")

                    for p in parts[1:]:

                        try:
                            val = int(p.split()[0], 16)

                            # heuristic: printable tag range
                            if 0x20 <= (val & 0xFF) <= 0x7E:

                                tag = val
                                break

                        except:
                            pass

                prev = listing.getInstructionBefore(prev.getAddress())

        except:
            pass

        func_containing = get_func(instr.getAddress())

        if tag is None:
            tag = 0x0

        if tag not in tag_map:
            tag_map[tag] = []

        tag_map[tag].append(
            (
                func_containing,
                instr.getAddress(),
                name
            )
        )


##########################################################################
# REPORT
##########################################################################

print("\n=== POOL TAG REPORT ===\n")

for tag in sorted(tag_map.keys()):

    print("TAG: 0x{:X}".format(tag))

    entries = tag_map[tag]

    print("  Allocations: {}".format(len(entries)))

    for f, addr, name in entries[:15]:

        fname = f.getName() if f else "<?>"

        print("    {} @ {} ({})".format(
            fname,
            addr,
            name
        ))

    print("")

print("Done.\n")