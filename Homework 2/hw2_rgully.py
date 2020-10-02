# CFRS 772 - Homework 2
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# Description:
#   This program will perform a string or binary search on
#   a user specified file and output results to console
#   and a file
#
# References:
#   https://stackoverflow.com/questions/4664850/find-all-occurrences-of-a-substring-in-python
#   https://stackoverflow.com/questions/5618988/regular-expression-parsing-a-binary-file
#   https://docs.python.org/3.1/library/binascii.html#binascii.b2a_hex
import re
import binascii


class TextFile:
    """
    Text file class which holds the absolute path to a text file
    to be searched upon.
    """

    # Initializing a new instantiation of a TextFile object
    def __init__(self, file_path):
        self.file_path = file_path
        self.type = "TextFile"

    # overriding the __str__ method to print out file_path and the class type
    def __str__(self):
        return f"fn = {self.file_path}, " \
               f"type = {self.type}"

    def keyword_search(self, key_word):
        """
        Keyword search performed against a text file using key_word,
        which was provided by the user. Will return a list of offsets
        where the keyword was located in the file at self.file_path.
        This search is case sensitive!
        :param key_word:
        :return:
        """

        # Attempt to open file and read to locate key_word
        try:
            # Read in all of the lines of the file
            file_object = open(self.file_path, "r")
            lines = file_object.read()
            file_object.close()

            # Use the regex module and list comprehensions to get offsets
            offsets = [m.start() for m in re.finditer(key_word, lines)]

            # Return the list of offsets
            return offsets

        # Catch the exception when an error occurs, and print it out.
        except Exception as e:
            print("\nSorry, an error occured: {0}".format(str(e)))
            exit(1)


class BinaryFile(TextFile):
    """
    Child of TextFile class which holds the absolute path to a binary file
    to be searched upon.
    """

    # Initializing a new instantiation of a BinaryFile object
    def __init__(self, file_path):
        TextFile.__init__(self, file_path)
        self.type = "BinaryFile"

    # Overriding the method to tweak it for binary files
    def keyword_search(self, key_word):
        """
        This is the binary string search version of keyword_search. Here,
        key_word is expected to be a string of hex characters.
            Example: ffd9
            Example: ffd8ffe0
        :return:
        """

        # Attempt to open file and read to locate key_word
        try:
            # Read in all of the lines of the file
            file_object = open(self.file_path, "rb")
            lines = file_object.read()
            file_object.close()

            # Use the regex module and list comprehensions to get offsets
            # Convert user's string to a binary literal using unhexlify()
            offsets = [m.start() for m in
                       re.finditer(binascii.unhexlify(key_word), lines)]

            # Return the list of offsets
            return offsets

        # Catch binascii error due to incorrect input.
        except binascii.Error as e:
            print("\nIncorrect input detected!"
                  "\nMake sure to enter your keyword in the expected format. "
                  "Ex:  ffd8ffe0")
            exit(1)

        # Catch other exceptions and print out an error message.
        except Exception as e:
            print("\nSorry, an error occured: {0}".format(str(e)))
            exit(1)


if __name__ == '__main__':

    """
    Main routine to take input from a user
    to perform binary/text keyword searches
    against specified files.
    """

    # Using a try/except clause to catch errors from user input
    try:
        # Prompt user for: filename/path, file type, and keyword
        file_path = input("Enter full path of desired file: ")
        file_type = input("Enter type of desired file (text/binary): ")

        # Check the requested file type to create the proper class
        if "text" in file_type:
            key_word = input("Enter keyword to search upon: ")
            # Create TextFile object
            text_file = TextFile(file_path)

            # Capture offsets
            offsets = text_file.keyword_search(key_word)

            # Change output based on results of the keyword search
            output = ""
            if len(offsets) == 0:
                output = "File searched: {1}\n" \
                         "Keyword provided: {0}\n" \
                         "No occurances of '{0}' found in {1}"\
                    .format(key_word, text_file.file_path)
            else:
                output = "File searched: {2}\n" \
                         "Keyword provided: {3}\n" \
                         "{0} occurances found at offsets: {1}"\
                    .format(len(offsets), offsets,
                            text_file.file_path, key_word)

            # Write to stdout: filename, keyword,
            #   if keyword was found, and offsets (if any)
            #   Send the same info to a new file
            print("\n"+output)
            out_file_name = "TextFile_Keyword_Search_-_"+key_word+".txt"
            out_file = open(out_file_name, "w")
            out_file.write(output)
            out_file.close()
            print("\nOutput written to: ", out_file_name)

        elif "binary" in file_type:
            key_word = input("Enter hex-string to search upon "
                             "(no spaces or delimiters; ex: ffd9): ")
            # Create BinaryFile object
            bin_file = BinaryFile(file_path)

            # Capture offsets
            offsets = bin_file.keyword_search(key_word)

            # Change output based on results of the keyword search
            output = ""
            if len(offsets) == 0:
                output = "File searched: {1}\n" \
                         "Keyword provided: {0}\n" \
                         "No occurances of '{0}' found in {1}"\
                    .format(binascii.unhexlify(key_word), bin_file.file_path)
            else:
                output = "File searched: {2}\n" \
                         "Keyword provided: {3}\n" \
                         "{0} occurances found at offsets: {1}"\
                    .format(len(offsets), offsets, bin_file.file_path,
                            binascii.unhexlify(key_word))

            # Write to stdout: filename, keyword,
            #   if keyword was found, and offsets (if any)
            #   Send the same info to a new file
            print("\n"+output)
            out_file_name = "BinaryFile_Keyword_Search_-_{0}.txt"\
                .format(key_word)
            out_file = open(out_file_name, "w")
            out_file.write(output)
            out_file.close()
            print("\nOutput written to: ", out_file_name)

        # Else exit the program because file type not recognized
        else:
            print("\nSorry, file type not recognized.")
            print("Please enter only 'text' or 'binary'.")

    # Catching keyboard interrupts to exit cleanly
    except KeyboardInterrupt:
        print("\nEnding program.")

    # Catching other Exceptions
    except Exception as e:
        print("\nSorry, an error occured: " + str(e))
