# Allocation / Free Correlator
#
# Detects possible memory/resource leaks by matching
# allocation calls with missing frees across CFG paths.
#
# @category Analysis

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.symbol import RefType
from ghidra.program.model.pcode import PcodeOp


##########################################################################
# CONFIG
##########################################################################

MAX_PATH_DEPTH = 20

ALLOC_FUNCS = set([
    "ExAllocatePool2",
    "ExAllocatePoolWithTag",
    "malloc",
    "new",
    "IoAllocateMdl",
    "FltAllocateContext",
])

FREE_FUNCS = set([
    "ExFreePool",
    "ExFreePool2",
    "free",
    "delete",
    "IoFreeMdl",
    "FltReleaseContext",
])


##########################################################################
# INIT
##########################################################################

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
bbm = BasicBlockModel(currentProgram)


##########################################################################
# FUNCTION LOOKUP
##########################################################################

def get_func(addr):
    return fm.getFunctionContaining(addr)


def is_alloc_call(func_name):
    return func_name in ALLOC_FUNCS


def is_free_call(func_name):
    return func_name in FREE_FUNCS


##########################################################################
# FIND CALLS IN FUNCTION
##########################################################################

def get_calls(func):

    calls = []

    it = listing.getInstructions(func.getBody(), True)

    while it.hasNext():

        instr = it.next()

        if not instr.getFlowType().isCall():
            continue

        refs = instr.getReferencesFrom()

        for r in refs:

            if not r.getReferenceType().isCall():
                continue

            target = getFunctionAt(r.getToAddress())

            if target is None:
                continue

            calls.append((instr, target))

    return calls


##########################################################################
# CFG WALK (simple DFS over basic blocks)
##########################################################################

def build_cfg(func):

    blocks = bbm.getCodeBlocksContaining(func.getBody(), monitor)

    graph = {}

    for b in blocks:

        graph[b] = []

        succ = b.getDestinations(monitor)

        while succ.hasNext():

            edge = succ.next()

            graph[b].append(edge.getDestinationBlock())

    return graph


##########################################################################
# FIND PATHS WITH ALLOC BUT NO FREE
##########################################################################

def dfs(block, graph, visited, depth, saw_alloc):

    if depth > MAX_PATH_DEPTH:
        return False

    if block in visited:
        return False

    visited.add(block)

    # scan instructions in block
    it = listing.getInstructions(block, True)

    local_alloc = saw_alloc
    local_free_seen = False

    while it.hasNext():

        instr = it.next()

        if not instr.getFlowType().isCall():
            continue

        refs = instr.getReferencesFrom()

        for r in refs:

            if not r.getReferenceType().isCall():
                continue

            func = getFunctionAt(r.getToAddress())

            if func is None:
                continue

            name = func.getName()

            if is_alloc_call(name):
                local_alloc = True

            if is_free_call(name):
                local_free_seen = True

    # terminal condition: free seen after alloc
    if local_alloc and not local_free_seen and len(graph[block]) == 0:
        return True

    # recurse
    leak_found = False

    for nxt in graph[block]:
        if dfs(nxt, graph, visited, depth + 1, local_alloc):
            leak_found = True

    return leak_found


##########################################################################
# ANALYSIS ENTRY
##########################################################################

print("\n=== ALLOCATION / FREE ANALYZER ===\n")

funcs = fm.getFunctions(True)

for func in funcs:

    calls = get_calls(func)

    alloc_sites = []

    for instr, callee in calls:

        if is_alloc_call(callee.getName()):
            alloc_sites.append(instr.getAddress())

    if len(alloc_sites) == 0:
        continue

    print("\nFunction: {}".format(func.getName()))

    graph = {}

    blocks = bbm.getCodeBlocksContaining(func.getBody(), monitor)

    for b in blocks:

        graph[b] = []

        succ = b.getDestinations(monitor)

        while succ.hasNext():

            edge = succ.next()

            graph[b].append(edge.getDestinationBlock())

    visited = set()

    for b in blocks:

        if dfs(b, graph, visited, 0, False):

            print("  Potential leak path starting in block:")
            print("    {}".format(b))

print("\nDone.\n")