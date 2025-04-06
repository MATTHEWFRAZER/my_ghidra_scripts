fm = currentProgram.getFunctionManager()
f = fm.getFunctionContaining(currentAddress)

operand_map = {
    "si": ["rsi", "esi"],
    "bx": ["rbx", "ebx"],
    "cx": ["rcx", "ecx"],
    "dx": ["rdx", "edx"],
    "ax": ["rax", "eax"],
    "8": ["r8", "r8d"],
    "9": ["r9", "r9d"],
    "10": ["r10", "r10d"],
    "11": ["r11", "r11d"],
    "12": ["r12", "r12d"],
    "13": ["r13", "r13d"],
    "14": ["r14", "r14d"],
    "15": ["r15", "r15d"],
}


def is_operand_a_match(operand, register):
    return any(x == operand.toString().lower() for x in operand_map[register])


def is_address_stop_condition(address, register):
    if f == address:
        return True

    instruction = currentProgram.getListing().getInstructionAt(address)

    # mov, lea, pop, xor (with self), cmov
    mnemonic = instruction.getMnemonicString()

    operands = instruction.getOpObjects(0)

    if any(
        x in mnemonic.lower() for x in ("mov", "lea", "pop", "cmov")
    ):  # handles things like movzx
        if is_operand_a_match(operands[0], register):
            return True
    elif mnemonic.lower() == "xor":
        if is_operand_a_match(operands[0], register) and is_operand_a_match(
            operands[1], register
        ):  # handles xor reg, reg
            return True

    return False


def get_xrefs_from_traceback(address, register):
    current = address
    #print(current, (current == None), "hicheck")
    while current:
        if is_address_stop_condition(current, register):
            return [], current
        instruction = currentProgram.getListing().getInstructionAt(current)
        fall_from = instruction.getFallFrom()
        # get xrefs
        ref_iter = instruction.getReferenceIteratorTo()
        xrefs = []
        for ref in ref_iter:
            # TODO: check ref type
            xrefs.append(ref.getFromAddress())
        #print(xrefs, "check references to")
        #print("fall_from", fall_from)
        if fall_from:
            if xrefs:
                xrefs.append(fall_from)
            # else:
            #    xrefs = [fall_from]
        if xrefs:
            #print("xrefs")
            return xrefs, None
        current = instruction.getPrevious().getAddress()
        #print("new current", current)

    #print("hi2")
    raise Exception("not supposed to be here")


def get_next_previous_addresses(address, register):
    # 1. find instruction that falls into current, trace back until
    #    we find xrefs or operation that we looking for
    # 2. find xrefs

    instruction = currentProgram.getListing().getInstructionAt(address)

    # get xrefs
    xrefs = instruction.getFlows()

    fall_from = instruction.getFallFrom()

    if is_address_stop_condition(address, register):
        #print("stop condition", address)
        return [], address
    if xrefs:
        #print("append")
        xrefs.append(fall_from)
        return xrefs, None
    else:
        #print("else")
        return get_xrefs_from_traceback(address, register)


def find_register_flow(register):
    stack = [(currentAddress, "")]
    #print(stack)
    visited = set()
    while stack:
        current, indent = stack.pop()
        visited.add(current)
        next_addresses, stop_address = get_next_previous_addresses(current, register)
        #print(next_addresses)
        if not next_addresses:
            #print("hi", stop_address)
            instruction = currentProgram.getListing().getInstructionAt(stop_address)
            print(str(current) + " <- " + str(stop_address) + ": " +  str(instruction))
            continue
        for address in next_addresses:
            if address not in visited:
                stack.append((address, indent + "  "))
                print(indent + str(current) + " <- " + str(address))
            else:
                #print(current)
                print(indent + str(current) + " <- " + str(address) + "(see " + str(address) + " above)")


register = askString("register: ", "What register flow would you like to calculate")
find_register_flow(register)
