# HW2_stub
# Jones: 
# ChangeLog: ...
#   jhj: create file object only, no method params at init

# imports here
import sys

# uncomment for debugging
#import pdb
#pdb.set_trace()
#


class BinFile:
    '''
    Purpose: finds occurrences of a searchTerm in a file
    Input: filename and searchTerm as string (hex characters)
    Output: offsets where searchTerm is found
    '''
    def __init__(self, filename):
        # set instance variables here; return a list of offsets (integers)
        self.filename = filename
        print('\nCreating BinFile object')

    def __str__(self):
        return "\nfilename = %s, filetype = binary, searchTerm = %s"
        % (self.filename, self.searchTerm)

    def findSearchTerm(self, searchTerm):
        self.searchTerm = searchTerm
        self.offsets = []
        # loop through the file here looking for search term
        return self.offsets


class TextFile:
    '''
    Purpose: finds occurrences of a searchTerm in a file
    Input: filename and searchTerm as string
    Output: offsets where searchTerm is found
    '''
    def __init__(self, filename):
        # set instance variables here; return a list of offsets (integers)
        self.filename = filename
        print('\nCreating TextFile object')

    def __str__(self):
        return "\nfilename = %s, filetype = text, searchTerm = %s"
        % (self.filename, self.searchTerm)

    def findSearchTerm(self, searchTerm):
        self.searchTerm = searchTerm
        self.offsets = []
        # loop through the file here looking for search term
        return self.offsets

# Local main for testing...
if __name__ == '__main__':
        # get user inputs
        filename = input("Enter filename (full path): ")
        filetype = input("Enter filetype (b or t): ")
        searchTerm = input("Enter search term (string or hex characters): ")
        # create object based on filetype
        if(filetype == 'b'):
                fObject = ### your code here...
        elif(filetype == 't'):
                fObject = ### your code here...
        else:
                print("Bad filetype; must be 't' or 'b'. Exiting\n")
                sys.exit(1)
        # output filename and search term to console and a file
        ### your code here...
        # call findSearchTerm method; capture results as variable result
        result = fObject.findSearchTerm(searchTerm)
        # output results to console and a file
        if not result:  # checks for empty result list
                print("Search term not found.\n")
                ### output to file also
        else:
                print("Search term found...\n")
                for i in result:
                        print("Offset: " + str(i) + "\n")
				### output to file also
