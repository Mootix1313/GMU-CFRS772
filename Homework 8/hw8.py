# CFRS 772 - Homework 8
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# Description:
#   This module will prompt a user to initiate a JPG retrieval of one of three
# 	JPGs from a website (http://www.xbit.cc/images/fileN.jpg).
# 	Will indicate to a user on:
# 		* Detected appended data at the end of the JPG footer
# 		* The filename of the JPG being checked
#
#   If appended data is found, it will be written to a file.


import urllib.request as req
import re


def get_jpg(url_num):
    """
    Function to retrieve a JPG from the user chosen link.
    :param url_num:
    :return jpg_data:
    """
    jpg_data = []
    base_url = r'http://www.xbit.cc/images/file'

    try:
        print("[\\]\tRetrieving file"+url_num+".jpg...")
        jpg_data = req.urlopen(str(base_url+url_num+'.jpg')).read()

    except Exception as e:
        print("[!]\tSorry, an error has occurred: \n[!]\t{0}".format(e))
        exit(1)

    return jpg_data


def check_file(jpg_file):
    """
    Will check the provided file for the jpg footer
        and for appended data past the jpg footer
    :param jpg_file:
    :return appended_data:
    """

    jpg_file_len = len(jpg_file)
    jpg_header_magic = b'\xff\xd8\xff\xe0'
    jpg_footer_magic = b'\xff\xd9'
    appended_data = []

    try:
        print("[\\]\tChecking file...")
        # Search for the JPG header magic to check if the file is a JPG
        header_match = re.search(jpg_header_magic, jpg_file)

        # If it is a JPG, check for the footer
        if header_match:
            # Attempt to calculate the beginning of the appended data
            footer_match = re.search(jpg_footer_magic, jpg_file)
            appended_data_start = footer_match.start(0) + 2
            append_data_size = jpg_file_len - appended_data_start

            # If there is appended data, return to user
            if append_data_size > 0:
                appended_data = jpg_file[appended_data_start:]

        # Print an error message when no JPG header is found!
        else:
            print("[!]\tERROR: JPG header magic not found!")
            exit(1)

    except Exception as e:
        print("[!]\tSorry, an error has occurred: \n\t\t{0}".format(e))
        exit(1)

    return appended_data


def user_prompt():
    """
    Module used to prompt a user for their choice of JPG
    :return the image number from the user:
    """
    try:
        return \
            input(
                "\n[->]\tWhich JPG image would you like to download (1-3)?: ")
    except KeyboardInterrupt:
        print("\n[\\]\tExiting due to CTRL+C...")
        exit(0)


if __name__ == '__main__':
    """
    Main routine to prompt a user for an image
        to download and check for appended data.
    """

    # Prompt user and check the file
    image_num = user_prompt()
    hidden_data = check_file(get_jpg(image_num))

    if hidden_data:
        print("[\\]\tAppended data discovered!")

        # Open a new file to write bytes, and then close the file
        new_file_name = str("file"+image_num+".jpg_appended")
        fd = open(new_file_name, "wb")
        fd.write(hidden_data)
        fd.close()

        print("[\\]\t{0} bytes were written to {1}\n"
              .format(len(hidden_data), new_file_name))
    else:
        print("[\\]\tNo appended data found in this JPG.")
