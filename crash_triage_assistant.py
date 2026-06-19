# Crash Triage Assistant (Static Postmortem Analyzer)
#
# Given a faulting instruction address, attempts to infer:
#   - likely crash reason
#   - pointer provenance (light trace)
#   - risky operations
#
# @category Analysis

from ghidra.program.model.pcode import PcodeOp


##########################################################################
# INPUT
##########################################################################

addr = currentAddress

instr = getInstructionAt(addr)

if instr is None:
    printerr("No instruction at selected address")
    exit()


print("\n=== CRASH TRIAGE ANALYSIS ===\n")
print("Faulting Address: {}\n".format(addr))


##########################################################################
# CLASSIFICATION HELPERS
##########################################################################

def is_memory_read(op):

    return op.getOpcode() in [PcodeOp.LOAD]


def is_memory_write(op):

    return op.getOpcode() in [PcodeOp.STORE]


def is_call(op):

    return op.getOpcode() == PcodeOp.CALL


##########################################################################
# ANALYZE INSTRUCTION
##########################################################################

ops = instr.getPcode()

risk_flags = []

reads = []
writes = []
calls = []


for op in ops:

    if is_memory_read(op):

        risk_flags.append("MEMORY_READ")

        for i in range(op.getNumInputs()):

            reads.append(op.getInput(i))

    if is_memory_write(op):

        risk_flags.append("MEMORY_WRITE")

        for i in range(op.getNumInputs()):

            writes.append(op.getInput(i))

    if is_call(op):

        risk_flags.append("CALL")


##########################################################################
# BASIC CRASH PATTERNS
##########################################################################

def detect_null_deref(text):

    if "00000000" in text or "NULL" in text:

        return True

    return False


def detect_user_ptr_risk(instr):

    text = str(instr)

    if "RCX" in text or "RDX" in text:

        if "MOV" in text or "CMP" in text:

            return True

    return False


text = str(instr)


if detect_null_deref(text):

    risk_flags.append("POSSIBLE_NULL_DEREF")

if detect_user_ptr_risk(instr):

    risk_flags.append("POSSIBLE_USER_POINTER_USAGE")


##########################################################################
# BACKWARD TRACE (LIGHTWEIGHT)
##########################################################################

def trace_source(vn, depth=0):

    if vn is None or depth > 5:
        return []

    try:

        def_op = vn.getDef()

        if def_op is None:
            return []

        opcode = def_op.getOpcode()

        if opcode == PcodeOp.COPY:

            return [("COPY", def_op.getInput(0))]

        if opcode == PcodeOp.LOAD:

            return [("LOAD", def_op.getInput(0))]

        if opcode == PcodeOp.CAST:

            return [("CAST", def_op.getInput(0))]

    except:
        pass

    return []


trace_results = []


for r in reads:

    try:
        trace_results.append(trace_source(r))
    except:
        pass


##########################################################################
# REPORT
##########################################################################

print("=== INSTRUCTION CONTEXT ===\n")
print(instr)

print("\n=== RISK FLAGS ===\n")

if len(risk_flags) == 0:
    print("No obvious issues detected")
else:
    for r in set(risk_flags):
        print("- {}".format(r))


print("\n=== MEMORY OPERANDS ===\n")

print("Reads:")
for r in reads:
    print("  {}".format(r))

print("\nWrites:")
for w in writes:
    print("  {}".format(w))


print("\n=== ROOT CAUSE HYPOTHESIS ===\n")

if "POSSIBLE_NULL_DEREF" in risk_flags:
    print("- Likely null pointer dereference")

if "MEMORY_READ" in risk_flags:
    print("- Instruction depends on memory state (possible stale pointer)")

if "CALL" in risk_flags:
    print("- Crash may originate from function pointer corruption")

if "POSSIBLE_USER_POINTER_USAGE" in risk_flags:
    print("- Possible unsafe user-mode pointer usage")


print("\n=== LIGHT TRACE BACK ===\n")

for t in trace_results:
    print(t)

print("\nDone.\n")