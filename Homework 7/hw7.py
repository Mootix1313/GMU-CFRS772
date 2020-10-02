# CFRS 772 - Homework 7
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# Description:
#   This module will take a memory image, and parse through
#   in search of _EPROCESS and _ETHREAD structures. Once found,
#   associated metadata will be printed out.
#
# Assumptions:
#   1. We're only going to open and parse the provided file "vm.vmem"

import re
import struct


def get_eprocess(fd):
    """
    Module to locate _EPROCESS blocks and print their
    Image Name, PID, and PPID.
    :param fd:
    :return:
    """

    eproc_magic = b'\x03\x00\x1B\x00\x00\x00\x00\x00'
    try:
        fd.seek(0)

        for match in re.finditer(eproc_magic, fd.read()):
            # move pointer to start of E_block
            current_eproc_head = match.start()

            # define offsets for metadata
            pid_offset = current_eproc_head+132
            ppid_offset = current_eproc_head+332
            name_offset = current_eproc_head+372

            # Get PID @offset 132 in eproc
            fd.seek(pid_offset)
            pid = struct.unpack("<I", fd.read(4))[0]

            # Continue past incorrect hits
            if pid == 0:
                continue

            # Get PPID at @offset 332
            fd.seek(ppid_offset)
            ppid = struct.unpack("<I", fd.read(4))[0]

            # Get the process's name @offset 372
            fd.seek(name_offset)
            proc_name = struct.unpack("<16s", fd.read(16))[0]

            # print metadata
            print("[+] Discovered {0} @ {1}\n"
                  "\t[\] PID: {2}\n"
                  "\t[\] PPID: {3}\n"
                  .format(str(proc_name, 'utf-8', errors='replace').
                          rstrip(" \00"),
                          hex(current_eproc_head),
                          pid, ppid))
    except Exception as e:
        print("Sorry, an error occurred: \n\t"
              "{0}".format(e))


def get_ethread(fd):
    """
    Module to locate _ETHREAD blocks and print their
    TID, and PPID.
    :param fd:
    :return:
    """

    # find ETHREAD headers
    ethread_magic = b'\x06\x00\x70\x00\x00\x00\x00\x00'
    fd.seek(0)

    for match in re.finditer(ethread_magic, fd.read()):
        # move pointer to start of E_block
        current_ethread_head = match.start()

        # define offsets for metadata
        cid_offset = current_ethread_head + 492

        # Get CID @offset 492 in eproc
        fd.seek(cid_offset)
        ppid = struct.unpack("<I", fd.read(4))[0]
        tid = struct.unpack("<I", fd.read(4))[0]

        # Continue past incorrect hits
        if ppid == 0:
            continue

        # print metadata
        print("[+] Discovered ETHREAD @ {0}\n"
              "\t[\] TID: {1}\n"
              "\t[\] PPID: {2}\n"
              .format(hex(current_ethread_head), tid, ppid))


if __name__ == '__main__':
    """
    Main routine for testing
    """

    # Attempt to open the memory dump
    try:
        fi = open("vm.vmem", "rb")

        # Parse _EPROCESS structs
        print("{0} _EPROCESS Structures {0}".format('-' * 20))
        get_eprocess(fi)

        # Parse _ETHREAD structs
        print("{0} _ETHREAD Structures {0}".format('-' * 20))
        get_ethread(fi)

    except FileNotFoundError:
        print("File not found")
        exit(1)
