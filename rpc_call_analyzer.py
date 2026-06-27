# Native RPC Call Analyzer
#
# Finds Windows RPC client calls and attempts to recover
# interface descriptors and likely target services.
#
# @category Analysis

from ghidra.program.model.symbol import RefType

RPC_APIS = {
    "NdrClientCall2",
    "NdrClientCall3",
    "Ndr64AsyncClientCall",
    "RpcBindingFromStringBindingW",
    "RpcBindingFromStringBindingA",
    "RpcBindingBind",
    "RpcBindingSetAuthInfoW",
    "RpcBindingSetAuthInfoA",
    "RpcEpResolveBinding",
    "RpcBindingFree"
}

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

def read_ascii(addr, maxlen=256):
    try:
        data = getDataAt(addr)
        if data:
            s = data.getValue()
            if isinstance(s, basestring):
                return s
    except:
        pass
    return None

def get_call_target(instr):
    for ref in instr.getReferencesFrom():
        if ref.getReferenceType().isCall():
            return getFunctionAt(ref.getToAddress())
    return None

print("========== Native RPC Analysis ==========\n")

for func in fm.getFunctions(True):

    it = listing.getInstructions(func.getBody(), True)

    while it.hasNext():

        ins = it.next()

        callee = get_call_target(ins)

        if callee is None:
            continue

        if callee.getName() not in RPC_APIS:
            continue

        print("Caller      : {}".format(func.getName()))
        print("Call Site   : {}".format(ins.getAddress()))
        print("RPC API     : {}".format(callee.getName()))

        #
        # Walk backwards looking for pushed addresses or LEA
        # that may reference binding strings or MIDL descriptors.
        #

        prev = ins.getPrevious()

        recovered = []

        for _ in range(25):

            if prev is None:
                break

            for ref in prev.getReferencesFrom():

                if ref.getReferenceType() in (RefType.DATA, RefType.READ):

                    s = read_ascii(ref.getToAddress())

                    if s:
                        recovered.append(
                            (ref.getToAddress(), s)
                        )

            prev = prev.getPrevious()

        if recovered:

            print("Recovered data:")

            seen = set()

            for addr, s in recovered:

                if s in seen:
                    continue

                seen.add(s)

                print("  {} -> {}".format(addr, s))

        print("")