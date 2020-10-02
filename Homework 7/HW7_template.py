# Jones
# Template for CFRS 772 Lab 7
# Expects Python 3.x (tested on 3.5.1 Win64)

# imports here (if any)
import re
import sys

# uncomment next two lines for debugging
#import pdb
#pdb.set_trace()


def getEprocess(fd):
    ''' Parses EPROCESS blocks
          Arguments: open file descriptor
          Returns: nothing
    '''
    # find EPROCESS headers
    E_P_HEADER = b'\x03\x00\x1B\x00\x00\x00\x00\x00'
    print("PROCESS PIDs and PPIDs\n")
    for match in re.finditer(E_P_HEADER, fd.read()):
        fd.seek(match.start())  # moves file pointer to start of E_block
        # HW: use struct.unpack to read two bytes at PID offset as variable pid
        # HW: your code goes here...
        print('PID: '+str(pid))
        # Dump PPID at offset + 332
        fd.seek(match.start())
        # HW: use struct.unpack to read two bytes at PPID offset as variable ppid
        # HW: your code goes here...
        print('PPID: '+str(ppid)+'\n')


def getEthread(fd):
    ''' Parses ETHREAD blocks
          Arguments: open file descriptor
          Returns: nothing
    '''
    # find ETHREAD headers
    E_T_HEADER = b'\x06\x00\x70\x00\x00\x00\x00\x00'
    print("THREAD parent process PIDs\n")
    for match in re.finditer(E_T_HEADER, fd.read()):
        fd.seek(match.start())
        # HW: use struct.unpack to read two bytes at PID offset as variable pid
        # HW: your code goes here...
        print('Parent PID: '+str(pid)+'\n')

# Local main for testing...
if __name__ == '__main__':
    # open the file and call the getFSinfo function
    try:
        fi = open(r'vm.vmem', 'rb')
    except FileNotFoundError:
        print("File not found")
        sys.exit(1)
    fi.seek(0)
    getEprocess(fi)
    fi.seek(0)
    getEthread(fi)
    fi.close()
