# CFRS 772 - Homework 5
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# Description:
#   This program is an updated version of the setupapi_parser.v2.py
#       from the Miller & Bryce book, Chapter 5. The edits provide
#       the module the ability to parse a given setupapi.app.log file
#       for stored command lines.
#
# Provided test files:
#   setupapi.dev.log: 0e0bd55731f317e054c00a78a2a4c200

import argparse
import re


def parse_setup_api(setup_log):
    """
    Read data from provided file for "cmd: "
    :param setup_log: str - Path to valid setup api log
    :return: a sorted list of unique commands parsed from the file
    """
    cmd_list = set()

    try:
        # read the lines of the log file
        log_lines = open(setup_log, 'r').readlines()

        # find all of the lines that start with "cmd: "
        #   only save the part after "cmd: "
        # Saving the list of commands as a set
        #   guarantees a unique list of commands from the file
        cmd_list = {m.group(0).strip("cmd: ")
                    for line in log_lines
                    for m in re.finditer(r"cmd:.*", line.strip())}

        # Catch the FileNotFoundError
        #   when a filename that doesn't exist is provided
    except FileNotFoundError:
        print("Provided file [{0}] does not exist".format(setup_log))
        exit(1)

    return sorted(cmd_list)


def pretty_print(cmd_list, setup_log):
    """
    Print out the list of commands parsed from the file
    :param cmd_list:
    :param setup_log:
    :return Nothing:
    """

    # Print output header
    print("\n"
          "{0} [ {2} Commands Found From {1} ] {0}"
          "\n".format('-'*60, setup_log, len(cmd_list)))

    # Print either the list of commands or an empty set message
    if len(cmd_list) > 0:
        for command in cmd_list:
            print(command)
    else:
        print("No commands were found in this file.")


# Main routine for collecting command line args and auto parsing a given file
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Module to parse "
                                                 "setupapi.app.log files for commands")
    parser.add_argument('IN_FILE', help='Windows 7 SetupAPI file')
    args = parser.parse_args()

    # Pretty print out the set of commands parsed from the provided file
    pretty_print(parse_setup_api(args.IN_FILE), args.IN_FILE)
