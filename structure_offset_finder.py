# Structure Offset Usage Finder
#
# Finds all memory accesses of the form:
#   [reg + constant]
#
# Groups by offset and reports usage sites.
#
# @category Analysis

from ghidra.program.model.lang import Register
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.address import Address


##########################################################################
# CONFIG
##########################################################################

MAX_RESULTS_PER_OFFSET = 200


##########################################################################
# DATA STRUCTURE
##########################################################################

offset_map = {}  # offset -> list of hits


class Hit(object):

    def __init__(self, func, addr, instr, base, offset):

        self.func = func
        self.addr = addr
        self.instr = instr
        self.base = base
        self.offset = offset


##########################################################################
# HELPERS
##########################################################################

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()


def get_func(addr):
    return fm.getFunctionContaining(addr)


def add_hit(offset, hit):

    if offset not in offset_map:
        offset_map[offset] = []

    if len(offset_map[offset]) > MAX_RESULTS_PER_OFFSET:
        return

    offset_map[offset].append(hit)


##########################################################################
# SCAN INSTRUCTIONS
##########################################################################

print("Scanning program for structure offsets...")

instr_iter = listing.getInstructions(True)

count = 0

while instr_iter.hasNext() and not monitor.isCancelled():

    instr = instr_iter.next()
    count += 1

    if count % 50000 == 0:
        print("Processed {} instructions".format(count))

    # We inspect pcode ops
    ops = instr.getPcode()

    for op in ops:

        opcode = op.getOpcode()

        # Look for LOAD / STORE with PTRSUB
        if opcode not in [PcodeOp.LOAD, PcodeOp.STORE]:
            continue

        # input[1] is typically address expression
        if op.getNumInputs() < 2:
            continue

        addr_node = op.getInput(1)

        if addr_node is None:
            continue

        # PTRSUB pattern: base + constant
        if addr_node.getOpcode() != PcodeOp.PTRSUB:
            continue

        base = addr_node.getInput(0)
        offset_node = addr_node.getInput(1)

        try:
            offset = offset_node.getOffset()
        except:
            continue

        func = get_func(instr.getAddress())

        hit = Hit(
            func,
            instr.getAddress(),
            instr,
            base,
            offset
        )

        add_hit(offset, hit)


##########################################################################
# REPORT
##########################################################################

print("\n=== STRUCTURE OFFSET USAGE REPORT ===\n")

for offset in sorted(offset_map.keys()):

    hits = offset_map[offset]

    print("OFFSET 0x{:X} ({} hits)".format(offset, len(hits)))

    for h in hits[:20]:

        fname = h.func.getName() if h.func else "<?>"

        print("  {} @ {}".format(fname, h.addr))

        print("     {}".format(h.instr))

    print("")

print("Done.")