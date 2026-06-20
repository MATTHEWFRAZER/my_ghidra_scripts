# Code Cave Detector
#
# Finds executable regions containing large runs of:
#   NOP
#   INT3
#   ZERO
#
# @category Analysis

from ghidra.program.model.address import AddressSet

MIN_CAVE_SIZE = 32

memory = currentProgram.getMemory()
fm = currentProgram.getFunctionManager()

print("\n=== CODE CAVE DETECTOR ===\n")

caves = []


def byte_at(addr):
    b = memory.getByte(addr)
    return b & 0xff


for block in memory.getBlocks():

    try:

        if not block.isExecute():
            continue

        start = block.getStart()
        end = block.getEnd()

        current_type = None
        cave_start = None
        cave_size = 0

        addr = start

        while addr.compareTo(end) <= 0:

            value = byte_at(addr)

            cave_type = None

            if value == 0x90:
                cave_type = "NOP"

            elif value == 0xCC:
                cave_type = "INT3"

            elif value == 0x00:
                cave_type = "ZERO"

            if cave_type is not None:

                if current_type is None:

                    current_type = cave_type
                    cave_start = addr
                    cave_size = 1

                elif cave_type == current_type:

                    cave_size += 1

                else:

                    if cave_size >= MIN_CAVE_SIZE:

                        caves.append(
                            (
                                cave_start,
                                addr.previous(),
                                cave_size,
                                current_type,
                                block.getName()
                            )
                        )

                    current_type = cave_type
                    cave_start = addr
                    cave_size = 1

            else:

                if current_type is not None:

                    if cave_size >= MIN_CAVE_SIZE:

                        caves.append(
                            (
                                cave_start,
                                addr.previous(),
                                cave_size,
                                current_type,
                                block.getName()
                            )
                        )

                current_type = None
                cave_start = None
                cave_size = 0

            addr = addr.next()

        if current_type and cave_size >= MIN_CAVE_SIZE:

            caves.append(
                (
                    cave_start,
                    end,
                    cave_size,
                    current_type,
                    block.getName()
                )
            )

    except:
        pass

##########################################################################
# REPORT
##########################################################################

caves.sort(
    key=lambda x: x[2],
    reverse=True
)

for start, end, size, cave_type, section in caves:

    print("==============================================")
    print("Section    : {}".format(section))
    print("Type       : {}".format(cave_type))
    print("Start      : {}".format(start))
    print("End        : {}".format(end))
    print("Size       : {} bytes".format(size))
    print("")

print("\nTotal caves found: {}\n".format(len(caves)))