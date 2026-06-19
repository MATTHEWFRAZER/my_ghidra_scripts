# IRP Dispatch Table Recovery
#
# Extracts DriverObject->MajorFunction[] assignments
# and reconstructs IRP handler mapping.
#
# @category Analysis

from ghidra.program.model.symbol import RefType
from ghidra.program.model.pcode import PcodeOp


##########################################################################
# IRP TABLE NAMES
##########################################################################

IRP_NAMES = {
    0x00: "IRP_MJ_CREATE",
    0x02: "IRP_MJ_CLOSE",
    0x03: "IRP_MJ_READ",
    0x04: "IRP_MJ_WRITE",
    0x0E: "IRP_MJ_DEVICE_CONTROL",
    0x0F: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    0x11: "IRP_MJ_POWER",
    0x12: "IRP_MJ_SYSTEM_CONTROL",
}


##########################################################################
# INIT
##########################################################################

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()


def get_func(addr):
    return fm.getFunctionContaining(addr)


##########################################################################
# FIND IRP ASSIGNMENTS
##########################################################################

print("\n=== IRP DISPATCH TABLE RECOVERY ===\n")

instr_iter = listing.getInstructions(True)

results = []

while instr_iter.hasNext() and not monitor.isCancelled():

    instr = instr_iter.next()

    # We only care about stores
    ops = instr.getPcode()

    for op in ops:

        if op.getOpcode() != PcodeOp.STORE:
            continue

        # STORE has 2 inputs:
        #   input[0] = address
        #   input[1] = value

        if op.getNumInputs() < 2:
            continue

        addr_node = op.getInput(0)
        val_node = op.getInput(1)

        if addr_node is None or val_node is None:
            continue

        addr_str = str(addr_node)

        # Look for pattern: MajorFunction
        if "MajorFunction" not in addr_str:
            continue

        try:
            offset = addr_node.getOffset()
        except:
            continue

        handler_addr = val_node.getAddress()

        handler_func = getFunctionAt(handler_addr)

        if handler_func is None:
            handler_func = getFunctionContaining(handler_addr)

        if handler_func is None:
            continue

        results.append(
            (offset, handler_func, instr.getAddress())
        )


##########################################################################
# PRINT RESULTS
##########################################################################

results.sort(key=lambda x: x[0])

for offset, func, addr in results:

    name = IRP_NAMES.get(offset, "IRP_MJ_???")

    print("{} (0x{:X})".format(name, offset))
    print("    Handler : {}".format(func.getName()))
    print("    At      : {}".format(addr))
    print("")

print("Done.\n")