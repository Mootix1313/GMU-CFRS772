# HW2_key
# Jones: Spring 2019
# ChangeLog:
#   jhj: create file object only, no method params at init

# imports here
import sys

# uncomment for debugging
# import pdb
# pdb.set_trace()
#


class BinFile:
    '''
    Purpose: creates binary file object
    Methods: findSearchTerm: finds occurrences of a searchTerm in a file
    Input: filename and searchTerm as string (hex characters)
    Output: offsets where searchTerm is found
    '''
    def __init__(self, filename):
        # set instance variables here; return a list of offsets (integers)
        self.filename = filename
        print('\nCreating BinFile object')

    def __str__(self):
        return "\nfilename = %s, filetype = binary, searchTerm = %s" \
            % (self.filename, self.searchTerm)

    def findSearchTerm(self, searchTerm):
        self.searchTerm = searchTerm
        self.offsets = []
        try:
            # stores the bytes (hex) string as array of ints (0..255)
            self.searchTerm = bytearray.fromhex(self.searchTerm)
        except:
            print("\nError converting search term hex string to bytearray - \
                  format is pairs of hex characters, \
                  spaces between pairs are optional.\n")
            sys.exit(1)
        termLen = len(self.searchTerm)
        match = 0
        with open(self.filename, 'rb') as f:
            byte = f.read(1)
            while(byte):
                # int.from_bytes casts the byte to corresponding int (0..255)
                if(int.from_bytes(byte, byteorder='big') ==
                   self.searchTerm[match]):
                    match += 1
                    if(match == termLen):
                        self.offsets.append(f.tell()-termLen)
                        match = 0
                else:
                    if(match != 0):
                        # if some has matched,
                        # back up one place before continuing
                        f.seek(f.tell() - 1)
                    match = 0
                byte = f.read(1)
        return self.offsets


class TextFile:
    '''
    Purpose: creates text file object
    Methods: findSearchTerm: finds occurrences of a searchTerm in a file
    Input: filename and searchTerm as string
    Output: offsets where searchTerm is found
    '''
    def __init__(self, filename):
        # set instance variables here; return a list of offsets (integers)
        self.filename = filename
        print('\nCreating TextFile object')

    def __str__(self):
        return "\nfilename = %s, filetype = text, searchTerm = %s" % \
            (self.filename, self.searchTerm)

    def findSearchTerm(self, searchTerm):
        self.searchTerm = searchTerm
        self.offsets = []
        termLen = len(self.searchTerm)
        match = 0
        with open(self.filename, 'r') as f:
            byte = f.read(1)
            while(byte):
                if(byte == self.searchTerm[match]):
                    match += 1
                    if(match == termLen):
                        self.offsets.append(f.tell()-termLen)
                        match = 0
                else:
                    if(match != 0):
                        # if some has matched, back up one
                        f.seek(f.tell() - 1)
                    match = 0
                byte = f.read(1)
        return self.offsets

# Local main for testing...
if __name__ == '__main__':
        # get user inputs
        filename = input("Enter filename (full path): ")
        filetype = input("Enter filetype (b or t): ")
        searchTerm = input("Enter search term (string or hex characters): ")
        # create object based on filetype
        if(filetype == 't'):
                fObject = TextFile(filename)
        elif(filetype == 'b'):
                fObject = BinFile(filename)
        else:
                print("Bad filetype; must be 't' or 'b'. Exiting\n")
                sys.exit(1)
        # output filename and search term to console and a file
        try:
            f = open("outfile.txt", 'w')
        except:
            print("Error opening outfile")
            sys.exit(1)
        print("\nFilename: "+filename)
        print("SearchTerm: "+searchTerm)
        f.write("Filename: "+filename+"\n")
        f.write("SearchTerm: "+searchTerm+"\n")
        # call findSearchTerm method; capture results as variable result
        result = fObject.findSearchTerm(searchTerm)
        # output results to console and a file
        if not result:  # checks for empty result list
                print("Search term not found.\n")
                f.write("Search term not found.\n")
        else:
                print("Search term found...\n")
                f.write("Search term found...\n\n")
                for i in result:
                        print("    Offset: " + str(i))
                        f.write("    Offset: " + str(i)+"\n")
        f.close()
