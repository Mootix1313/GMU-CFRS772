import sys

text_characters = {chr(x) for x in range(32, 127)} | {x for x in "\n\r\t\b"}
table = str.maketrans(dict.fromkeys(text_characters))


def istextfile(filename, blocksize = 4096):
    return istext(open(filename).read(blocksize))


def istext(s):
    if "\0" in s:
        return False
    
    if not s:  # Empty files are considered text
        return True

    # Get the non-text characters (maps a character to itself then
    # use the 'remove' option to get rid of the text characters.)
    t = s.translate(table)

    # If more than 30% non-text characters, then
    # this is considered a binary file
    if len(t)/len(s) > 0.30:
        return False
    return True
