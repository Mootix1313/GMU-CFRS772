# CFRS 772 - Homework 9
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# Usage:
#   python hw9.py <pcap_to_parse>
#
# Description:
# 	This module aims to parse a PCAP file for unique IPv4
#   and MAC addresses. It will then take that data set and
#   insert them into an sqlite3 database.
#
# Assumptions:
#   1. Only dealing with PCAP files, and not PCAPNG.
#   2. Assume that all IP headers are 20 bytes in len (no options)
#   3. Database schema is:
#       Table_1:  IP_Address    | Packet_Count
#       Table_2:  MAC_Address   | Packet_Count
#
# Resources:
#   https://sqlite.org/lang_conflict.html
#   https://stackoverflow.com/questions/
#       5181927/efficient-way-to-ensure-unique-rows-in-sqlite3

import sqlite3
import argparse
import struct

# Global variables referencing the endpoints db...
# this is to get around the fact that endpoints() can only take in
#   a PCAP file as a parameter, and is assumed to write to the db, too.
# DB name
endpoints_db = 'endpoints.db'
tbl_ip_addresses = 'tbl_ip_addresses'
tbl_mac_addresses = 'tbl_mac_addresses'


def create_new_db():
    """
    Function used to create a new Database for testing
    :return name of newly created DB:
    """

    # IP Addresses table, field, and field type.
    ip_address_field = 'ip_address'
    packet_count_field = 'packet_count_ip'

    # MAC Addresses table, field, and field type.
    mac_address_field = 'mac_address'
    packet_count_field_mac = 'packet_count_mac'

    # common db variables
    address_field_type = 'TEXT'
    count_field_type = 'INTEGER'

    try:
        # Connect to the db and create a cursor to exec upon
        connection = sqlite3.connect(endpoints_db)
        cursor_1 = connection.cursor()

        # Actual command to create the ip and mac address tables
        create_command_ip = \
            "CREATE TABLE {0} ({1} {2}, {3} {4}, " \
            "PRIMARY KEY ({1}) ON CONFLICT REPLACE)" \
            .format(
                tbl_ip_addresses, ip_address_field, address_field_type,
                packet_count_field, count_field_type)

        create_command_mac = \
            "CREATE TABLE {0} ({1} {2}, {3} {4}, " \
            "PRIMARY KEY ({1}) ON CONFLICT REPLACE)" \
            .format(
                tbl_mac_addresses, mac_address_field, address_field_type,
                packet_count_field_mac, count_field_type)

        # Execute the commands
        cursor_1.execute(create_command_ip)
        cursor_1.execute(create_command_mac)

        # Commit the changes to the DB and Close
        connection.commit()
        connection.close()

        print("[\\] Successfully performed: \n\t{0}\n\t{1}".format(
            create_command_ip, create_command_mac))

    except Exception as e:
        # if the database already exists, just return the db info
        if "exists" in str(e):
            print("[!] {} already exists!".format(endpoints_db))
            return [endpoints_db, tbl_ip_addresses, tbl_mac_addresses]
        else:
            print(f"[!] Sorry, an error occurred in create_new_db: \n\t{e}")
            exit(1)

    # return new db info
    return [endpoints_db, tbl_ip_addresses, tbl_mac_addresses]


def is_pcap(magic_value):
    """
    This function takes in a 4-byte magic value to determine
        if a file is a PCAP file or not
    :param magic_value:
    :return boolean:
    """
    pcap_magic = b'\xd4\xc3\xb2\xa1'

    if magic_value == pcap_magic:
        return True
    return False


def open_pcap(file_to_open):
    """
    Function used to open a pcap file for reading.
    Will check to see if provided file is a pcap based on
    magic value.
    """
    pcap_file = ''

    try:
        pcap_file = open(file_to_open, 'rb')

        if not is_pcap(pcap_file.read(4)):
            print("[!] [{0}] is not a PCAP file!".format(pcap_file.name))
            exit(1)
        else:
            pcap_file.seek(0)
    except FileNotFoundError:
        print("[!] Sorry, [{0}] does not exist".format(file_to_open))
        exit(1)

    return pcap_file


def close_pcap(pcap_file):
    """
    will close the provided pcap file
    :param pcap_file:
    """
    pcap_file.close()


def parse_pcap(pcap_file):
    """
    Parse a PCAP file for IPv4 and MAC addresses.
    :return generator for IPv4 and PAC+:
    """

    global_pcap_header_size = 24
    packet_header_size = 16
    eth_header_size = 14
    ip_header_size = 20
    type_ipv4 = 8

    # for storing the parsed IPv4 and MAC addresses
    ip_list = []
    mac_list = []

    try:
        # Seek to first packet header
        pcap_file.seek(global_pcap_header_size)

        # Read through the PCAP file until we reach EOF
        while True:
            # Read packet header, and unpack using a Struct format
            curr_packet_header = \
                struct.unpack(
                    '<IIII', pcap_file.read(packet_header_size)
                )

            # Capture the packet len and discovered offset
            packet_len = curr_packet_header[3]
            packet_offset = pcap_file.tell()
            end_of_curr_packet = packet_offset + packet_len

            # Read in the ETH header for MAC addresses
            #   curr_eth_header[0] == dst_MAC
            #   curr_eth_header[1] == src_MAC
            #   cur_eth_header[2] == type (looking for 0x0800)
            curr_eth_header = struct.unpack(
                '<6s6sH', pcap_file.read(eth_header_size)
            )

            # formatting the dst mac addr
            dst = curr_eth_header[0]
            dst_string = "{}:{}:{}:{}:{}:{}".format(
                format(dst[0], 'x'), format(dst[1], 'x'),
                format(dst[2], 'x'), format(dst[3], 'x'),
                format(dst[4], 'x'), format(dst[5], 'x'))

            # formatting the src mac addr
            src = curr_eth_header[1]
            src_string = "{}:{}:{}:{}:{}:{}".format(
                format(src[0], 'x'), format(src[1], 'x'),
                format(src[2], 'x'), format(src[3], 'x'),
                format(src[4], 'x'), format(src[5], 'x'))

            # actually add the addresses to the mac list
            mac_list.append(dst_string)
            mac_list.append(src_string)

            if curr_eth_header[2] == type_ipv4:
                # Then read the IP header for IPv4 addresses
                #   curr_ip_header[8] == src_addr_ipv4
                #   curr_ip_header[9] == dst_addr_ipv4
                curr_ip_header = struct.unpack(
                    '!BBHHHBBH4s4s', pcap_file.read(ip_header_size))

                # format the ip src addr
                ip_src = curr_ip_header[8]
                ip_src_string = "{}.{}.{}.{}".format(
                    format(ip_src[0], 'd'), format(ip_src[1], 'd'),
                    format(ip_src[2], 'd'), format(ip_src[3], 'd'))

                # format the ip dst addr
                ip_dst = curr_ip_header[9]
                ip_dst_string = "{}.{}.{}.{}".format(
                    format(ip_dst[0], 'd'), format(ip_dst[1], 'd'),
                    format(ip_dst[2], 'd'), format(ip_dst[3], 'd'))

                ip_list.append(ip_src_string)
                ip_list.append(ip_dst_string)

            # Lastly, seek to next packet
            pcap_file.seek(end_of_curr_packet)

    except struct.error:
        # Expect to throw at struct.error when we've reached EOF
        # pcap_file.read(n) should produce an empty string at EOF
        return ip_list, mac_list
    except Exception as e:
        print("[!] Sorry, an error occurred in parse_pcap: ")
        print("\t {0}".format(e))
        exit(1)


def uniq_addresses(ip_list, mac_list):
    """
    Takes total list of IPv4 and MAC addresses, obtains the count, and returns
    two dictionaries of {"<address>": packet_count}
    :param ip_list
    :param mac_list:
    :return two dictionaries of {"<address>": packet_count}:
    """
    # create a set of the addresses to dedupe
    ip_set = sorted(set(ip_list))
    mac_set = sorted(set(mac_list))

    # create a dictionary of {"<ip_address>": packet_count}
    ip_dict = [(ip, ip_list.count(ip)) for ip in ip_set]

    # create a dictionary of {"<mac_address>": packet_count}
    # mac_dict = {mac: mac_list.count(mac) for mac in mac_set}
    mac_dict = [(mac, mac_list.count(mac)) for mac in mac_set]

    # return a sorted list of addrs, key is packet count
    return (
        sorted(ip_dict, key=lambda ip: ip[1]),
        sorted(mac_dict, key=lambda mac: mac[1]))


def write_to_db(ip_dict, mac_dict):
    """
    Takes in dictionaries to write to endpoints.db
    :param ip_dict:
    :param mac_dict:
    """
    # Assumed schema:
    #       Table_1:  IP_Address    | Packet_Count
    #       Table_2:  MAC_Address   | Packet_Count
    try:
        # connect to the database
        conn = sqlite3.connect(endpoints_db)

        # create a cursor
        curse = conn.cursor()

        # insert commands
        insert_command_ip = "INSERT INTO {0} VALUES (?, ?)" \
            .format(tbl_ip_addresses)

        insert_command_mac = "INSERT INTO {0} VALUES (?, ?)" \
            .format(tbl_mac_addresses)

        # Insert ip addresses into the database
        for ip, count in ip_dict:
            curse.execute(insert_command_ip, (ip, count))

        # Insert mac addresses into the database
        for mac, count in mac_dict:
            curse.execute(insert_command_mac, (mac, count))

        # Commit and Close
        conn.commit()
        conn.close()

        print("[\\] Successfully performed: \n\t{0}\n\t{1}".format(
            insert_command_ip, insert_command_mac
        ))

    except Exception as e:
        print("[!] Sorry, an error occurred: \n\t" + str(e))
        exit(1)


def get_record(db_name, table_name):
    """
    Function to print out result of (select * from table_name) from db_name
    :param db_name
    :param table_name:
    """

    try:
        # connect to the database
        conn = sqlite3.connect(db_name)

        # create a cursor
        curse = conn.cursor()

        # Select records from the ip address table
        fetch_command = "SELECT * FROM {0}".format(table_name)
        curse.execute(fetch_command)

        print("[\\] Results from {}:\n".format(table_name))
        for result in curse.fetchall():
            print("\t{}".format(result))

        # Commit and Close
        conn.commit()
        conn.close()

        print("[\\] Successfully performed: \n\t{}".format(fetch_command))

    except Exception as e:
        print("[!] Sorry, an error occurred in get_record: \n\t" + str(e))
        exit(1)


def endpoints(pcap_name):
    """
    Will recieve a pcap to parse for unique IPv4 and MAC addresses.
    Will take those sets
    :return:
    """
    try:
        # open the file for parsing
        pcap_file = open_pcap(pcap_name)
        print("[\] Successfully opened \"{}\"".format(pcap_name))

        # parse the pcap for IPv4 and MAC addresses
        ip_list, mac_list = parse_pcap(pcap_file)

        # close the file when we're done
        close_pcap(pcap_file)

        # get counts for each address and dedupe the list
        ip_dict, mac_dict = uniq_addresses(ip_list, mac_list)

        # write the unique data to endpoints.db
        write_to_db(ip_dict, mac_dict)
    except Exception as e:
        print("[!] Sorry, an error occurred in endpoints: \n\t" + str(e))
        exit(1)


def setup():
    """
    function to setup arguments
    :return received args from the command line:
    """

    print("{0} HW9:  rgully4's PCAP Processing Script {0}".format('-' * 20))

    module_desc = \
        "Module wil parse PCAP for IPv4 and MAC addresses. " \
        "It will write the unique sets to enpoints.db."

    parser = argparse.ArgumentParser(
        description=module_desc)

    parser.add_argument("pcap", help="PCAP file to parse")

    args = parser.parse_args()

    print("[\\] Preparing to parse \"{}\"".format(args.pcap))

    return args


if __name__ == '__main__':
    """
    Main routine to create an enpoints db,
    Parse a PCAP file for IPv4 and MAC addresses,
    and then enter a deduped list into the db.
    """

    # Set up arguments for the module
    args = setup()

    # Create the endpoints db, or check if it already exits
    create_new_db()

    # call endpoints to:
    #   1. Parse the pcap
    #   2. Dedupe discovered addresses and count them
    #   3. Write data to endpoints.db
    endpoints(args.pcap)

    # print out db for testing
    get_record(endpoints_db, tbl_ip_addresses)
    get_record(endpoints_db, tbl_mac_addresses)
