# CFRS 772 - Homework 10
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# Description:
#   This module aims to detect five different types of files:
#   a BMP, a plain text, a key logging file, a process monitoring file,
#   or a screenshot. Each detection method is based upon some of the traits
#   observed in exemplars of each kind.
#
# Usage:
#   python hw10.py <directory>
#
# Assumptions:
#   1. All BMP files have the same size info header and structure
#
# Resources:
#   1. https://en.wikipedia.org/wiki/BMP_file_format#File_structure
#   2. https://stackoverflow.com/questions/11968976/
#       list-files-only-in-the-current-directory
#   3. https://stackoverflow.com/questions/
#       4987327/how-do-i-check-if-a-string-is-unicode-or-ascii
#   4. https://github.com/ActiveState/code/tree/
#       master/recipes/Python/173220_test_if_file_or_string_text_or

import struct
import re
import argparse


def is_bmp(filename):
    """
    Detects if a file is a BMP, or not.
    :param filename:
    :return boolean:
    """
    bmp_file = False
    bmp_magic = b'\x42\x4d'
    magic_size = 2

    try:
        # open the file and check the magic value
        test_file = open(filename, "rb")
        if test_file.read(magic_size) == bmp_magic:
            bmp_file = True

        # close when we're done
        test_file.close()

    except Exception as e:
        print("[!] Sorry, an error occurred in is_bmp: \n\t" + str(e))
        exit(1)

    return bmp_file


def is_screenshot(filename):
    """
    Will determine if the given file is a screenshot, or not.
    Screenshots have the characteristics of being a BMP file,
    lacking "resolution" info, a have a color depth of 32, and is of the
    proper size (no small images).
    :param filename:
    :return:
    """
    screenshot = False
    bmp_head_size = 14

    # bar of entry: is this a BMP file?
    if is_bmp(filename):
        try:
            # open the file and seek to the info header
            bmp = open(filename, "rb")
            bmp.seek(bmp_head_size)

            # capture the header size, and read the info header
            dib_header_size = struct.unpack("<I", bmp.read(4))[0]
            bmp.seek(bmp_head_size)
            dib_header = struct.unpack("<IIIHHIIIIII",
                                       bmp.read(dib_header_size))

            # if there is no resolution info, and color depth == 32,
            # we have a screenshot
            if (dib_header[1] > 1000 or dib_header[2] > 1000) \
                    and (dib_header[4] == 32) and \
                    (dib_header[7] == 0 and dib_header[8] == 0):
                screenshot = True

            # close the file when we're done
            bmp.close()
        except Exception as e:
            print("[!] Sorry, an error occurred in is_screenshot: "
                  "\n\t" + str(e))
            exit(1)

    return screenshot


def is_text(filename):
    """
    Determines if a file is a plain text file based on the ability to decode
    a portion of it's contents as ASCII, and the ratio of ASCII chars
    contained in the file.
    This is a modified version of Ref #4.
    :param filename:
    :return:
    """
    chunk_size = 4096
    istext = True

    try:
        # open the file and grab a chunk
        file = open(filename, "rb")
        file_data = file.read(chunk_size)
        file.close()

        # if the ratio of non-ascii to total chars is gt 20% this is not a
        #   plain text file
        if text_ratio(file_data) > .2:
            istext = False

    # if the chunk can't be decoded, then we don't have a plain text file
    except UnicodeDecodeError:
        istext = False
    except Exception as e:
        print("[!] Sorry, an error occurred in is_text: "
              "\n\t" + str(e))
        exit(1)

    return istext


def text_ratio(data_chunk):
    """
    Gets the ratio of non-ascii to total chars in the data chunk
    :param data_chunk:
    :return:
    """
    # mapping of text chars that looks like {<ascii char>: None}
    text_characters = {chr(x) for x in range(32, 127)} | {x for x in
                                                          "\n\r\t\b"}
    table = str.maketrans(dict.fromkeys(text_characters))

    # Decode and translate the chunk to determine ratio of non-ascii chars
    translated = data_chunk.decode('ascii').translate(table)

    return len(translated) / len(data_chunk)


def is_keylog(filename):
    """
    Checks to see if the provided file is a keylogger, based on a collection
    of keywords in a known keylogging format...
    :param filename:
    :return:
    """
    keylogger = False
    chunk_size = 4096

    # collection of keywords, or patterns
    vv_pattern = "vv"
    keylog_pattern = "closing down keylogger"
    clipboard_pattern = "\n\nClipboard:  "
    total_regex = "({}|{}|{})".format(
        vv_pattern, keylog_pattern, clipboard_pattern)

    if is_text(filename):
        try:
            file = open(filename, "rb")
            data = file.read(chunk_size).decode("ascii").lower()
            file.close()

            if len(re.findall(total_regex, data)) > 0:
                keylogger = True
        except Exception as e:
            print("[!] Sorry, an error occurred in is_text: "
                  "\n\t" + str(e))
            exit(1)

    return keylogger


def is_process_monitor(filename):
    """
    Checks to see if the provided file is a process monitor log.
    We're keying in on:
        ====
        instance of Win32_Process
        {
    :param filename:
    :return:
    """
    proc_mon_pattern = "====\r\ninstance of Win32_Process\r\n{"
    chunk_size = 4096
    isprocmon = False

    if is_text(filename):
        try:
            # open the file and grab a chunk
            text_file = open(filename, "rb")
            chunk = text_file.read(chunk_size)
            text_file.close()
            # look for the proc_mon_pattern
            if len(re.findall(proc_mon_pattern, chunk.decode('ascii'))) > 0:
                isprocmon = True
        except Exception as e:
            print("[!] Sorry, an error occurred in is_process_monitor: "
                  "\n\t" + str(e))
            exit(1)

    return isprocmon


def try_test_files(directory):
    import os

    # get all files in
    files_in_dir = [
        os.path.join(directory, fn) for fn in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, fn))
    ]

    # capture the matching file names
    screenshot_found = []
    keylogger_found = []
    procmon_found = []
    all_else = []

    # test the files found in the directory
    for name in files_in_dir:
        try:
            if is_screenshot(name):
                screenshot_found.append(name)
            elif is_process_monitor(name):
                procmon_found.append(name)
            elif is_keylog(name):
                keylogger_found.append(name)
            else:
                all_else.append(name)

        except Exception as e:
            print("[!] Sorry, an error occurred in try_test_files: "
                  "\n\t" + str(e))
            exit(1)

    # Print results
    print("[\\] {0} files tested. Results: \n".format(len(files_in_dir)))

    # sceenshots
    print("[\\] {0} screenshots detected. \n".format(len(screenshot_found)))
    if len(screenshot_found) > 0:
        for file in screenshot_found:
            print("\t * {}\n".format(file))

    # Process Monitor
    print("[\\] {0} process monitors detected. \n".format(len(procmon_found)))
    if len(procmon_found) > 0:
        for file in procmon_found:
            print("\t * {}\n".format(file))

    # Keylogger
    print("[\\] {0} key logs detected. \n".format(len(keylogger_found)))
    if len(keylogger_found) > 0:
        for file in keylogger_found:
            print("\t * {}\n".format(file))

    # everything else
    print("[\\] {0} of everything else... \n".format(len(all_else)))


def setup():
    """
    function to setup arguments
    :return received args from the command line:
    """

    print("{0} HW10:  rgully4's File Matching Script {0}".format('-' * 20))

    module_desc = \
        "Module will attempt to identify keylogger, " \
        "process monitor, or screenshot files."

    parser = argparse.ArgumentParser(
        description=module_desc)

    parser.add_argument("directory", help="directory to begin search")

    args = parser.parse_args()

    print("[\\] Running module against \"{}\"".format(args.directory))

    return args


if __name__ == "__main__":
    """
    Main module for getting a directory to test against
    """
    test_dir = setup().directory
    try_test_files(test_dir)
