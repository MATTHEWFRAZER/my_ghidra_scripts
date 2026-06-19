# Process Monitoring Coverage Analyzer
#
# Builds a visibility map for security products
# and kernel drivers.
#
# @category Analysis

from collections import defaultdict

##########################################################################
# MONITORING APIS
##########################################################################

MONITORING_APIS = {

    "Process Monitoring": [
        "PsSetCreateProcessNotifyRoutine",
        "PsSetCreateProcessNotifyRoutineEx",
        "PsSetCreateProcessNotifyRoutineEx2"
    ],

    "Thread Monitoring": [
        "PsSetCreateThreadNotifyRoutine"
    ],

    "Image Load Monitoring": [
        "PsSetLoadImageNotifyRoutine"
    ],

    "Handle Monitoring": [
        "ObRegisterCallbacks"
    ],

    "Registry Monitoring": [
        "CmRegisterCallback",
        "CmRegisterCallbackEx"
    ],

    "Filesystem Monitoring": [
        "FltRegisterFilter",
        "FltStartFiltering"
    ],

    "Network Monitoring": [
        "FwpsCalloutRegister0",
        "FwpsCalloutRegister1",
        "FwpmCalloutAdd0",
        "FwpmCalloutAdd1"
    ],

    "ETW Monitoring": [
        "EtwRegister",
        "EtwWrite",
        "EtwEventRegister"
    ]
}

##########################################################################
# INIT
##########################################################################

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

##########################################################################
# STORAGE
##########################################################################

coverage = defaultdict(list)

##########################################################################
# HELPER
##########################################################################

def get_called_function(instr):

    refs = instr.getReferencesFrom()

    for ref in refs:

        if ref.getReferenceType().isCall():

            f = getFunctionAt(ref.getToAddress())

            if f:
                return f

    return None

##########################################################################
# SCAN
##########################################################################

print("\n=== PROCESS MONITORING COVERAGE ANALYZER ===\n")

for func in fm.getFunctions(True):

    try:

        instr_iter = listing.getInstructions(
            func.getBody(),
            True
        )

        while instr_iter.hasNext():

            instr = instr_iter.next()

            called = get_called_function(instr)

            if not called:
                continue

            callee_name = called.getName()

            for category, apis in MONITORING_APIS.items():

                if callee_name in apis:

                    coverage[category].append(
                        (
                            func.getName(),
                            instr.getAddress(),
                            callee_name
                        )
                    )

    except:
        continue

##########################################################################
# REPORT
##########################################################################

print("\n=== COVERAGE SUMMARY ===\n")

for category in sorted(MONITORING_APIS.keys()):

    if category in coverage:

        print("[YES] {}".format(category))

    else:

        print("[NO ] {}".format(category))

##########################################################################
# DETAILED RESULTS
##########################################################################

print("\n=== DETAILED RESULTS ===\n")

for category in sorted(coverage.keys()):

    print("\n------------------------------------------------")
    print(category)
    print("------------------------------------------------")

    for func_name, addr, api in coverage[category]:

        print("API      : {}".format(api))
        print("Function : {}".format(func_name))
        print("Address  : {}".format(addr))
        print("")

##########################################################################
# SCORECARD
##########################################################################

print("\n=== MONITORING SCORECARD ===\n")

score = 0

weights = {

    "Process Monitoring": 3,
    "Thread Monitoring": 2,
    "Image Load Monitoring": 3,
    "Handle Monitoring": 4,
    "Registry Monitoring": 2,
    "Filesystem Monitoring": 3,
    "Network Monitoring": 4,
    "ETW Monitoring": 2
}

for category, weight in weights.items():

    if category in coverage:
        score += weight

print("Coverage Score: {}".format(score))

if score >= 18:
    print("Visibility: HIGH")

elif score >= 10:
    print("Visibility: MODERATE")

else:
    print("Visibility: LOW")

print("\nDone.\n")