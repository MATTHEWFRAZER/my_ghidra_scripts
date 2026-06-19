# Acquire / Release Asymmetry Detector
#
# Detects imbalance between lock acquisition and release
# in kernel-mode drivers. This script while useful is
# not nearlly as robust as its angr equivalent. This
# looks at instructions, angr will trace actual paths.
#
# Flags:
#   - missing release paths
#   - potential deadlock risks
#   - asymmetric lock usage
#
# @category Analysis

from collections import defaultdict


##########################################################################
# INIT
##########################################################################

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()


##########################################################################
# PATTERNS
##########################################################################

ACQUIRE_PATTERNS = [
    "KeAcquireSpinLock",
    "KeAcquireInStackQueuedSpinLock",
    "KeAcquireInStackQueuedSpinLockAtDpcLevel",
    "ExAcquireFastMutex",
    "ExAcquireResourceExclusiveLite",
    "ExAcquireResourceSharedLite",
    "FltAcquirePushLock"
]

RELEASE_PATTERNS = [
    "KeReleaseSpinLock",
    "KeReleaseInStackQueuedSpinLock",
    "ExReleaseFastMutex",
    "ExReleaseResourceLite",
    "FltReleasePushLock"
]


##########################################################################
# STATE
##########################################################################

lock_state = defaultdict(lambda: {"acquire": 0, "release": 0})
function_map = {}


def get_func(addr):
    return fm.getFunctionContaining(addr)


##########################################################################
# SCAN FUNCTIONS
##########################################################################

print("\n=== LOCK ACQUIRE/RELEASE ASYMMETRY ANALYSIS ===\n")

funcs = fm.getFunctions(True)

for func in funcs:

    acq = 0
    rel = 0
    suspicious_calls = []

    instr_iter = listing.getInstructions(func.getBody(), True)

    while instr_iter.hasNext() and not monitor.isCancelled():

        instr = instr_iter.next()

        text = str(instr)

        ##################################################################
        # DETECT ACQUIRE
        ##################################################################

        for pat in ACQUIRE_PATTERNS:

            if pat in text:

                acq += 1
                suspicious_calls.append(("ACQUIRE", pat, instr.getAddress()))

        ##################################################################
        # DETECT RELEASE
        ##################################################################

        for pat in RELEASE_PATTERNS:

            if pat in text:

                rel += 1
                suspicious_calls.append(("RELEASE", pat, instr.getAddress()))


    lock_state[func.getName()]["acquire"] = acq
    lock_state[func.getName()]["release"] = rel


##########################################################################
# REPORTING
##########################################################################

print("\n=== FUNCTION LOCK BALANCE REPORT ===\n")

for func, stats in lock_state.items():

    acq = stats["acquire"]
    rel = stats["release"]

    if acq == 0 and rel == 0:
        continue

    imbalance = acq - rel

    print("Function: {}".format(func))
    print("  Acquire count : {}".format(acq))
    print("  Release count : {}".format(rel))

    if imbalance > 0:
        print("  ⚠ POSSIBLE LOCK LEAK (missing release: {})".format(imbalance))

    elif imbalance < 0:
        print("  ⚠ POSSIBLE DOUBLE RELEASE / LOGIC ERROR (extra release: {})".format(-imbalance))

    else:
        print("  Balanced lock usage")

    print("")


##########################################################################
# GLOBAL SUMMARY
##########################################################################

total_acq = sum(v["acquire"] for v in lock_state.values())
total_rel = sum(v["release"] for v in lock_state.values())

print("\n=== GLOBAL SUMMARY ===\n")
print("Total acquires : {}".format(total_acq))
print("Total releases : {}".format(total_rel))

if total_acq > total_rel:
    print("⚠ GLOBAL IMBALANCE: potential leak paths exist")

elif total_rel > total_acq:
    print("⚠ GLOBAL IMBALANCE: potential over-release or logic error")

else:
    print("Lock usage globally balanced")

print("\nDone.\n")