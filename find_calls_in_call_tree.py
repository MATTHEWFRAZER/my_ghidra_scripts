# Finds all call chains from a start function to a target function.
#
# Features:
#   - Non-recursive DFS
#   - Prebuilt call graph
#   - Thunk resolution
#   - Cursor or manual start selection
#   - Stores instruction objects
#   - Prints full chain with callsite addresses
#
# @category Analysis

from collections import deque

MAX_DEPTH = 25


fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()


##########################################################################
# Utilities
##########################################################################

def find_function(name):

    funcs = fm.getFunctions(True)

    while funcs.hasNext():

        f = funcs.next()

        if f.getName() == name:
            return f

    return None


def resolve_thunk(func):

    if func is None:
        return None

    try:

        if func.isThunk():

            thunk_target = func.getThunkedFunction(True)

            if thunk_target is not None:
                return thunk_target

    except:
        pass

    return func


##########################################################################
# Edge
##########################################################################

class CallEdge(object):

    def __init__(
        self,
        caller,
        callee,
        instruction,
        thunk_name=None):

        self.caller = caller
        self.callee = callee
        self.instruction = instruction
        self.thunk_name = thunk_name


##########################################################################
# Build graph
##########################################################################

def build_call_graph():

    graph = {}

    funcs = fm.getFunctions(True)

    count = 0

    while funcs.hasNext() and not monitor.isCancelled():

        func = funcs.next()

        count += 1

        if count % 500 == 0:
            print("Processed {} functions".format(count))

        edges = []

        instrs = listing.getInstructions(
            func.getBody(),
            True)

        while instrs.hasNext():

            instr = instrs.next()

            if not instr.getFlowType().isCall():
                continue

            refs = instr.getReferencesFrom()

            for ref in refs:

                if not ref.getReferenceType().isCall():
                    continue

                target_addr = ref.getToAddress()

                callee = getFunctionAt(target_addr)

                if callee is None:
                    callee = getFunctionContaining(target_addr)

                if callee is None:
                    continue

                original_name = None

                if callee.isThunk():
                    original_name = callee.getName()

                callee = resolve_thunk(callee)

                edge = CallEdge(
                    func,
                    callee,
                    instr,
                    original_name)

                edges.append(edge)

        graph[func] = edges

    return graph


##########################################################################
# Path Helpers
##########################################################################

def path_contains_function(path, func):

    if len(path) == 0:
        return False

    if path[0].caller == func:
        return True

    for edge in path:

        if edge.callee == func:
            return True

    return False


##########################################################################
# Pretty Printing
##########################################################################

def print_chain(path):

    final_edge = path[-1]

    print("")
    print("=" * 80)
    print("TARGET REACHED")
    print("=" * 80)
    print("")

    print(
        "Final Caller : {}".format(
            final_edge.caller.getName()))

    print(
        "Target Callsite : {}".format(
            final_edge.instruction.getAddress()))

    print("")

    print("CALL CHAIN")
    print("")

    for edge in path:

        print(edge.caller.getName())

        if edge.thunk_name is not None:

            print(
                "    -> {} (via thunk {})".format(
                    edge.callee.getName(),
                    edge.thunk_name))

        else:

            print(
                "    -> {}".format(
                    edge.callee.getName()))

        print(
            "       Address     : {}".format(
                edge.instruction.getAddress()))

        print(
            "       Instruction : {}".format(
                edge.instruction))

        print("")

    print("=" * 80)
    print("")


##########################################################################
# Input
##########################################################################

use_cursor = askYesNo(
    "Start Function",
    "Use function under cursor?")

if use_cursor:

    start_func = getFunctionContaining(currentAddress)

    if start_func is None:

        printerr(
            "Cursor is not inside a function")

        exit()

else:

    start_name = askString(
        "Start Function",
        "Enter start function name")

    start_func = find_function(start_name)

    if start_func is None:

        printerr(
            "Failed to locate {}".format(
                start_name))

        exit()

target_name = askString(
    "Target Function",
    "Enter target function name")

target_func = find_function(target_name)

if target_func is None:

    printerr(
        "Failed to locate {}".format(
            target_name))

    exit()


target_func = resolve_thunk(target_func)

print("")
print("Building call graph...")
print("")

call_graph = build_call_graph()

print("")
print("Graph build complete")
print("")

##########################################################################
# DFS
##########################################################################

#
# stack entry:
#
# (
#   current_function,
#   path_to_here
# )
#

stack = deque()

stack.append(
    (
        start_func,
        []
    )
)

matches = 0

while len(stack) > 0 and not monitor.isCancelled():

    current_func, current_path = stack.pop()

    if len(current_path) >= MAX_DEPTH:
        continue

    edges = call_graph.get(
        current_func,
        [])
    
    for edge in edges:
        new_path = list(current_path)

        new_path.append(edge)

        if edge.callee == target_func:

            matches += 1

            print_chain(new_path)

            continue

        if path_contains_function(
            current_path,
            edge.callee):
            continue

        stack.append(
            (
                edge.callee,
                new_path
            )
        )

print("")
print("Done")
print("Matches Found: {}".format(matches))
print("")