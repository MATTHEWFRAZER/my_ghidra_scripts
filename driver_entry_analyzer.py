# DriverEntry Analyzer
#
# Builds a high-level behavioral summary of a Windows driver
# starting from DriverEntry.
#
# @category Analysis

from collections import defaultdict


##########################################################################
# INIT
##########################################################################

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()


def get_func(addr):
    return fm.getFunctionContaining(addr)


##########################################################################
# FIND DRIVERENTRY
##########################################################################

def find_driver_entry():

    funcs = fm.getFunctions(True)

    for f in funcs:

        name = f.getName().lower()

        if "driverentry" in name:
            return f

    return None


driver_entry = find_driver_entry()

if driver_entry is None:

    printerr("DriverEntry not found")
    exit()


print("\n=== DRIVER ENTRY ANALYSIS ===\n")
print("DriverEntry: {}\n".format(driver_entry.getName()))


##########################################################################
# ANALYSIS STORAGE
##########################################################################

allocs = []
devices = []
symlinks = []
callbacks = []
irps = defaultdict(str)


##########################################################################
# SCAN DRIVERENTRY BODY
##########################################################################

instr_iter = listing.getInstructions(driver_entry.getBody(), True)

while instr_iter.hasNext() and not monitor.isCancelled():

    instr = instr_iter.next()

    text = str(instr)

    refs = instr.getReferencesFrom()

    for r in refs:

        if r.getReferenceType().isCall():

            callee = getFunctionAt(r.getToAddress())

            if callee is None:
                continue

            name = callee.getName()

            ##################################################################
            # DEVICE CREATION
            ##################################################################

            if "IoCreateDevice" in name:
                devices.append((name, instr.getAddress()))

            if "IoCreateSymbolicLink" in name:
                symlinks.append((name, instr.getAddress()))

            ##################################################################
            # CALLBACK REGISTRATION
            ##################################################################

            if "PsSet" in name or "CmRegister" in name or "ObRegister" in name:
                callbacks.append((name, instr.getAddress()))

            if "FltRegister" in name or "Fwps" in name:
                callbacks.append((name, instr.getAddress()))

            ##################################################################
            # ALLOCATION EARLY
            ##################################################################

            if "ExAllocatePool" in name:
                allocs.append((name, instr.getAddress()))


##########################################################################
# IRP TABLE DETECTION (light heuristic reuse)
##########################################################################

instr_iter = listing.getInstructions(driver_entry.getBody(), True)

while instr_iter.hasNext():

    instr = instr_iter.next()

    text = str(instr)

    if "MajorFunction" in text:

        irps[text] = instr.getAddress()


##########################################################################
# REPORT
##########################################################################

print("=== DEVICE OBJECTS ===\n")

for d, addr in devices:

    print("{} @ {}".format(d, addr))

print("\n=== SYMBOLIC LINKS ===\n")

for s, addr in symlinks:

    print("{} @ {}".format(s, addr))

print("\n=== CALLBACK REGISTRATIONS ===\n")

for c, addr in callbacks:

    print("{} @ {}".format(c, addr))

print("\n=== EARLY ALLOCATIONS ===\n")

for a, addr in allocs:

    print("{} @ {}".format(a, addr))

print("\n=== IRP DISPATCH REFERENCES ===\n")

for k, v in irps.items():

    print("{} @ {}".format(k, v))


##########################################################################
# HIGH-LEVEL CLASSIFICATION
##########################################################################

print("\n=== DRIVER TYPE INFERENCE ===\n")

score = defaultdict(int)

for d, _ in devices:
    score["Device Driver"] += 3

for c, _ in callbacks:

    if "Ps" in c:
        score["Process Monitor"] += 2

    if "Cm" in c:
        score["Registry Filter"] += 2

    if "Flt" in c:
        score["Filesystem Filter"] += 3

    if "Fwps" in c:
        score["Network Filter"] += 3

for a, _ in allocs:
    score["Stateful Driver"] += 1

for k, v in sorted(score.items(), key=lambda x: -x[1]):

    print("{} : {}".format(k, v))


print("\nDone.\n")