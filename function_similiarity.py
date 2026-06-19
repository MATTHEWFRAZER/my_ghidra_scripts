# Function Similarity Engine
#
# Clusters functions by structural similarity:
#   - call patterns
#   - API usage
#   - string references
#   - basic block structure
#
# @category Analysis

from collections import defaultdict


##########################################################################
# INIT
##########################################################################

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()


##########################################################################
# FEATURE EXTRACTION
##########################################################################

def get_calls(func):

    calls = set()

    it = listing.getInstructions(func.getBody(), True)

    while it.hasNext():

        instr = it.next()

        if not instr.getFlowType().isCall():
            continue

        refs = instr.getReferencesFrom()

        for r in refs:

            if r.getReferenceType().isCall():

                target = getFunctionAt(r.getToAddress())

                if target is not None:
                    calls.add(target.getName())

    return calls


def get_strings(func):

    strings = set()

    it = listing.getInstructions(func.getBody(), True)

    while it.hasNext():

        instr = it.next()

        refs = instr.getReferencesFrom()

        for r in refs:

            if r.getReferenceType().isRead():

                try:
                    val = getDataAt(r.getToAddress())

                    if val is not None:

                        s = str(val)

                        if len(s) > 3:
                            strings.add(s)

                except:
                    pass

    return strings


def get_basic_blocks(func):

    blocks = 0

    it = listing.getInstructions(func.getBody(), True)

    for _ in it:
        blocks += 1

    return blocks


def get_instruction_count(func):

    count = 0

    it = listing.getInstructions(func.getBody(), True)

    while it.hasNext():
        it.next()
        count += 1

    return count


##########################################################################
# FINGERPRINT
##########################################################################

def fingerprint(func):

    return {
        "name": func.getName(),
        "calls": get_calls(func),
        "strings": get_strings(func),
        "blocks": get_basic_blocks(func),
        "instrs": get_instruction_count(func)
    }


##########################################################################
# SIMILARITY SCORE
##########################################################################

def similarity(f1, f2):

    score = 0

    # call overlap
    call_overlap = len(f1["calls"].intersection(f2["calls"]))
    score += call_overlap * 3

    # string overlap
    string_overlap = len(f1["strings"].intersection(f2["strings"]))
    score += string_overlap * 4

    # structure similarity
    block_diff = abs(f1["blocks"] - f2["blocks"])
    instr_diff = abs(f1["instrs"] - f2["instrs"])

    if block_diff < 3:
        score += 5

    if instr_diff < 20:
        score += 3

    return score


##########################################################################
# BUILD FINGERPRINTS
##########################################################################

print("\n=== BUILDING FUNCTION FINGERPRINTS ===\n")

funcs = list(fm.getFunctions(True))

fps = {}

for f in funcs:

    try:
        fps[f] = fingerprint(f)
    except:
        continue


##########################################################################
# COMPARE FUNCTIONS
##########################################################################

print("\n=== FUNCTION SIMILARITY RESULTS ===\n")

THRESHOLD = 8

seen = set()

for f1 in funcs:

    if f1 not in fps:
        continue

    for f2 in funcs:

        if f2 not in fps:
            continue

        if f1 == f2:
            continue

        pair = tuple(sorted([f1.getName(), f2.getName()]))

        if pair in seen:
            continue

        seen.add(pair)

        score = similarity(fps[f1], fps[f2])

        if score >= THRESHOLD:

            print("SIMILAR FUNCTIONS:")
            print("  {} <-> {}".format(
                f1.getName(),
                f2.getName()))

            print("  Score: {}".format(score))
            print("")

print("Done.\n")