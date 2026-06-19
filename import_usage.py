# Import Usage Ranking + Behavioral Fingerprint
#
# Produces ranked list of API usage across the binary:
#   - frequency per API
#   - per-function usage
#   - subsystem hints
#
# @category Analysis

from collections import defaultdict


##########################################################################
# INIT
##########################################################################

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()


##########################################################################
# STORAGE
##########################################################################

api_count = defaultdict(int)
api_by_func = defaultdict(lambda: defaultdict(int))


##########################################################################
# HELPERS
##########################################################################

def get_func(addr):
    return fm.getFunctionContaining(addr)


def get_called_function(instr):

    refs = instr.getReferencesFrom()

    for r in refs:

        if r.getReferenceType().isCall():

            f = getFunctionAt(r.getToAddress())

            if f is not None:
                return f

    return None


##########################################################################
# SCAN
##########################################################################

print("\n=== IMPORT USAGE RANKING ===\n")

instr_iter = listing.getInstructions(True)

while instr_iter.hasNext() and not monitor.isCancelled():

    instr = instr_iter.next()

    if not instr.getFlowType().isCall():
        continue

    func = get_called_function(instr)

    if func is None:
        continue

    name = func.getName()

    caller = get_func(instr.getAddress())

    caller_name = caller.getName() if caller else "<?>"

    api_count[name] += 1
    api_by_func[caller_name][name] += 1


##########################################################################
# RANKED OUTPUT
##########################################################################

print("\n=== TOP APIs (GLOBAL) ===\n")

sorted_apis = sorted(api_count.items(), key=lambda x: -x[1])

for api, count in sorted_apis[:50]:

    print("{} : {}".format(api, count))


##########################################################################
# PER-FUNCTION BREAKDOWN
##########################################################################

print("\n=== PER-FUNCTION API USAGE ===\n")

for func, apis in api_by_func.items():

    print("\nFunction: {}".format(func))

    sorted_local = sorted(apis.items(), key=lambda x: -x[1])

    for api, count in sorted_local[:10]:

        print("  {} : {}".format(api, count))


##########################################################################
# SUBSYSTEM HEURISTIC CLASSIFICATION
##########################################################################

print("\n=== SUBSYSTEM HEURISTICS ===\n")

def classify(api):

    if "Zw" in api or "Nt" in api:
        return "Kernel/System Calls"

    if "ExAllocate" in api or "Rtl" in api:
        return "Memory / Runtime"

    if "Flt" in api or "Io" in api:
        return "Filesystem / Driver I/O"

    if "Fwps" in api or "Fwpm" in api:
        return "Network Filtering (WFP)"

    if "Ps" in api:
        return "Process / Thread Monitoring"

    if "Ob" in api:
        return "Object / Handle Security"

    if "Cm" in api:
        return "Registry Monitoring"

    return "Other"


subsystem = defaultdict(int)

for api, count in api_count.items():

    subsystem[classify(api)] += count


for k, v in sorted(subsystem.items(), key=lambda x: -x[1]):

    print("{} : {}".format(k, v))


print("\nDone.\n")