# Cross-Binary Function Matcher
#
# Matches functions between two loaded Ghidra programs
# using structural + behavioral similarity.
#
# @category Analysis

from collections import defaultdict


##########################################################################
# INPUT PROGRAMS
##########################################################################

progA = currentProgram

progB = askProgram("Select comparison program")


fmA = progA.getFunctionManager()
fmB = progB.getFunctionManager()

listingA = progA.getListing()
listingB = progB.getListing()


##########################################################################
# HELPERS
##########################################################################

def get_calls(prog, listing, func):

    calls = set()

    it = listing.getInstructions(func.getBody(), True)

    while it.hasNext():

        instr = it.next()

        refs = instr.getReferencesFrom()

        for r in refs:

            if r.getReferenceType().isCall():

                f = prog.getFunctionManager().getFunctionAt(r.getToAddress())

                if f:
                    calls.add(f.getName())

    return calls


def get_strings(listing, func):

    strings = set()

    it = listing.getInstructions(func.getBody(), True)

    while it.hasNext():

        instr = it.next()

        refs = instr.getReferencesFrom()

        for r in refs:

            if r.getReferenceType().isRead():

                try:

                    s = str(getDataAt(r.getToAddress()))

                    if len(s) > 3:
                        strings.add(s)

                except:
                    pass

    return strings


def fingerprint(prog, listing, func):

    calls = get_calls(prog, listing, func)
    strings = get_strings(listing, func)

    count = 0

    it = listing.getInstructions(func.getBody(), True)

    while it.hasNext():
        it.next()
        count += 1

    return {
        "name": func.getName(),
        "calls": calls,
        "strings": strings,
        "instrs": count
    }


##########################################################################
# BUILD FINGERPRINTS
##########################################################################

print("\n=== BUILDING FUNCTION FINGERPRINTS ===\n")

fpsA = {}
fpsB = {}

funcsA = list(fmA.getFunctions(True))
funcsB = list(fmB.getFunctions(True))


for f in funcsA:

    try:
        fpsA[f] = fingerprint(progA, listingA, f)
    except:
        continue


for f in funcsB:

    try:
        fpsB[f] = fingerprint(progB, listingB, f)
    except:
        continue


##########################################################################
# SIMILARITY FUNCTION
##########################################################################

def similarity(f1, f2):

    score = 0

    call_overlap = len(f1["calls"].intersection(f2["calls"]))
    score += call_overlap * 4

    string_overlap = len(f1["strings"].intersection(f2["strings"]))
    score += string_overlap * 5

    if abs(f1["instrs"] - f2["instrs"]) < 10:
        score += 3

    return score


##########################################################################
# MATCHING
##########################################################################

print("\n=== FUNCTION MATCHING ===\n")

THRESHOLD = 10

matches = {}

usedB = set()

for fa in funcsA:

    if fa not in fpsA:
        continue

    best_match = None
    best_score = 0

    for fb in funcsB:

        if fb not in fpsB:
            continue

        score = similarity(fpsA[fa], fpsB[fb])

        if score > best_score:

            best_score = score
            best_match = fb

    if best_match and best_score >= THRESHOLD:

        matches[fa.getName()] = (best_match.getName(), best_score)

        usedB.add(best_match)


##########################################################################
# REPORT
##########################################################################

print("\n=== MATCH RESULTS ===\n")

for a, (b, score) in matches.items():

    print("{}  <-->  {}   (score={})".format(
        a, b, score))


##########################################################################
# UNMATCHED FUNCTIONS (POTENTIAL DIFFS)
##########################################################################

print("\n=== UNMATCHED FUNCTIONS (A) ===\n")

for f in funcsA:

    if f.getName() not in matches:

        print(f.getName())


print("\n=== UNMATCHED FUNCTIONS (B) ===\n")

for f in funcsB:

    if f not in usedB:

        print(f.getName())


print("\nDone.\n")