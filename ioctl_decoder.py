# IOCTL Decoder Recovery + Clustering
#
# Extracts IOCTL dispatch logic from drivers:
#   - switch/cmp IOCTL values
#   - handler mapping
#   - clustered IOCTL constants
#
# @category Analysis

from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import RefType


##########################################################################
# INIT
##########################################################################

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()


def get_func(addr):
    return fm.getFunctionContaining(addr)


##########################################################################
# STORAGE
##########################################################################

ioctl_map = {}      # ioctl_value -> handler
ioctl_refs = {}     # ioctl_value -> list of instr addresses


##########################################################################
# DETECT IOCTL CONSTANTS
##########################################################################

print("\n=== IOCTL DISCOVERY ===\n")

instr_iter = listing.getInstructions(True)

while instr_iter.hasNext() and not monitor.isCancelled():

    instr = instr_iter.next()

    ops = instr.getPcode()

    for op in ops:

        if op.getOpcode() not in [PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL]:
            continue

        if op.getNumInputs() < 2:
            continue

        a = op.getInput(0)
        b = op.getInput(1)

        val = None

        # detect constant IOCTL patterns
        try:
            if a.isConstant():
                val = a.getOffset()
            elif b.isConstant():
                val = b.getOffset()
        except:
            continue

        if val is None:
            continue

        # heuristic: IOCTL range detection (common Windows pattern)
        if val < 0x222000 or val > 0x23FFFF:
            continue

        func = get_func(instr.getAddress())

        if func is None:
            continue

        if val not in ioctl_refs:
            ioctl_refs[val] = []

        ioctl_refs[val].append(instr.getAddress())

        ioctl_map[val] = func.getName()


##########################################################################
# DETECT SWITCH-BASED IOCTL DISPATCH
##########################################################################

print("Scanning for switch dispatch patterns...\n")

for instr in listing.getInstructions(True):

    ops = instr.getPcode()

    for op in ops:

        if op.getOpcode() != PcodeOp.CBRANCH:
            continue

        # heuristic: compare against constant IOCTL
        if op.getNumInputs() < 2:
            continue

        cond = op.getInput(1)

        try:
            if cond.isConstant():

                val = cond.getOffset()

                if 0x222000 <= val <= 0x23FFFF:

                    func = get_func(instr.getAddress())

                    if func is not None:

                        ioctl_map[val] = func.getName()

                        if val not in ioctl_refs:
                            ioctl_refs[val] = []

                        ioctl_refs[val].append(instr.getAddress())

        except:
            continue


##########################################################################
# REPORT
##########################################################################

print("\n=== IOCTL REPORT ===\n")

sorted_keys = sorted(ioctl_refs.keys())

for val in sorted_keys:

    print("IOCTL 0x{:X}".format(val))

    print("  Handler : {}".format(
        ioctl_map.get(val, "UNKNOWN")))

    for addr in ioctl_refs[val][:10]:

        print("    at {}".format(addr))

    print("")


##########################################################################
# CLUSTER ANALYSIS
##########################################################################

print("\n=== IOCTL CLUSTERING ===\n")

clusters = {}

for val in sorted_keys:

    base = val & 0xFFFFC000  # coarse grouping heuristic

    if base not in clusters:
        clusters[base] = []

    clusters[base].append(val)


for base in sorted(clusters.keys()):

    vals = clusters[base]

    print("Cluster 0x{:X}".format(base))

    for v in vals:

        print("  0x{:X}".format(v))

    print("")


print("Done.\n")