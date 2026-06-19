# User -> Kernel Trust Boundary Analyzer
#
# Finds likely trust-boundary code paths and scores them
# according to validation quality.
#
# @category Analysis

from collections import defaultdict

##########################################################################
# CONFIG
##########################################################################

COPY_APIS = set([
    "memcpy",
    "memmove",
    "RtlCopyMemory",
    "RtlMoveMemory"
])

VALIDATION_APIS = set([
    "ProbeForRead",
    "ProbeForWrite",
    "MmProbeAndLockPages",
    "MmGetSystemAddressForMdlSafe"
])

IOCTL_APIS = set([
    "ZwDeviceIoControlFile",
    "NtDeviceIoControlFile"
])

##########################################################################
# INIT
##########################################################################

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

##########################################################################
# HELPERS
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
# ANALYSIS
##########################################################################

results = []

print("\n=== USER -> KERNEL TRUST BOUNDARY ANALYSIS ===\n")

for func in fm.getFunctions(True):

    score = 0
    findings = []

    validation_seen = False
    copy_seen = False

    try:

        instr_iter = listing.getInstructions(
            func.getBody(),
            True
        )

        while instr_iter.hasNext():

            instr = instr_iter.next()

            text = str(instr)

            ##################################################################
            # Call analysis
            ##################################################################

            called = get_called_function(instr)

            if called:

                name = called.getName()

                if name in VALIDATION_APIS:

                    validation_seen = True
                    findings.append(
                        "Validation API: {}".format(name)
                    )

                if name in COPY_APIS:

                    copy_seen = True
                    score += 3

                    findings.append(
                        "Memory copy: {}".format(name)
                    )

                if name in IOCTL_APIS:

                    score += 5

                    findings.append(
                        "DeviceIoControl path"
                    )

            ##################################################################
            # User pointer indicators
            ##################################################################

            lower = text.lower()

            if "userbuffer" in lower:

                score += 10

                findings.append(
                    "IRP->UserBuffer reference"
                )

            if "type3inputbuffer" in lower:

                score += 12

                findings.append(
                    "METHOD_NEITHER input"
                )

            if "mdladdress" in lower:

                score += 4

                findings.append(
                    "MDL usage"
                )

            if "systembuffer" in lower:

                score += 2

                findings.append(
                    "SystemBuffer usage"
                )

            ##################################################################
            # Potential length variables
            ##################################################################

            if "length" in lower:

                score += 1

                findings.append(
                    "Length-related logic"
                )

        ##################################################################
        # Function-name heuristics
        ##################################################################

        lname = func.getName().lower()

        if "ioctl" in lname:

            score += 15

            findings.append(
                "Likely IOCTL handler"
            )

        if "devicecontrol" in lname:

            score += 15

            findings.append(
                "DeviceControl handler"
            )

        if "dispatch" in lname:

            score += 5

            findings.append(
                "Dispatch routine"
            )

        ##################################################################
        # Validation scoring
        ##################################################################

        if score > 0:

            if not validation_seen:

                score += 10

                findings.append(
                    "No obvious validation API observed"
                )

            if copy_seen and not validation_seen:

                score += 5

                findings.append(
                    "Copy operation without obvious validation"
                )

            results.append(
                (
                    score,
                    func,
                    findings
                )
            )

    except:
        continue

##########################################################################
# REPORT
##########################################################################

results.sort(
    reverse=True,
    key=lambda x: x[0]
)

for score, func, findings in results[:100]:

    print("===================================================")
    print("Function : {}".format(func.getName()))
    print("Address  : {}".format(func.getEntryPoint()))
    print("Risk     : {}".format(score))
    print("")

    seen = set()

    for f in findings:

        if f in seen:
            continue

        seen.add(f)

        print("  - {}".format(f))

    print("")

print("\nDone.\n")