# CFRS 772 - Homework 6
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# Description:
# 	This script reads in a PCAP file to extract
# 	the data portion of ICMP packets. If the MD5 hash
# 	value of the data IS NOT equal to B97D6CFCE32659677B4B801CAA1754B8,
# 	then the data will be output to an output file.
#
# References:
#   https://gist.github.com/unitycoder/a82365a93c9992f7f9631741fe007e9d
#   http://www.tcpdump.org/linktypes.html
#   https://en.wikipedia.org/wiki/Ethernet_frame
#   https://en.wikipedia.org/wiki/IPv4#Packet_structure
#   https://github.com/afabbro/netinet/blob/master/ip.h
#   http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#   http://www.networksorcery.com/enp/protocol/icmp.htm
#   https://stackoverflow.com/questions/20768107/regarding-struct-unpack-in-python
#
# Assumptions:
#   1. Capture file hss network of type ETH
#   2. Assume PCAP files processed will have an eth.type of 0x0800 (IPv4)
#   3. Assume that all IP headers are 20 bytes in len (no options)

"""
1. PCAP Global Header structure (24-Bytes total)
{
    magic_number[0:4]; (4-bytes)
    version_major;  (2-bytes)
    version_minor;  (2-bytes)
    thiszone; (4-bytes; normally zero)
    sigfigs; (4-bytes; normally zero)
    snaplen; (4-bytes; max normally 65535)
    network; (4-bytes; 1==ETH)
}

2. PCAP Packet Header structure (16-Bytes total)
Read like: struct.unpack('<IIII', pcap.read(16))
{
    ts_sec; (4-bytes; secs since Unix-Epoch)
    ts_usec; (4-bytes; micro-secs since capture began)
    incl_len; (4-bytes; num of octets of packet saved in pcap)
    orig_len; (4-bytes; actual packet len)
}

3. org_len bytes immediately follows the header as the Packet's data

4. Ether Structure
Read like: struct.unpack('<6s6sH', curr_packet[0:14])
{
    ether_dhost[0:6]; (6-Bytes; MAC address of dest)
    ether_shost[6:12]; (6-Bytes; MAC address of source)
    ether_type[12:14]; (2-Bytes; 0x0800==IPv4; 0x0805==ARP; etc.)
    data[14:14+data_len]; (46-1500 bytes)
    frame_check; (4-bytes)
}

5. IPv4 Structure (Min size of 20-bytes; continued from eth_header)
Read like: struct.unpack('!BBHHHBBH4s4s', curr_packet[14:14+20])
{
    version[14]; (4-bits; value of 4 for IPv4)
    IHL[14]; (4-bits; header length)
    DSCP[15]; (6-bits; normally zero)
    ECN[15]; (2-bits; normally zero)
    tot_len[16:17]; (2-Bytes)
    identification[18:20]; (2-Bytes)
    flags[20:22]; (3-bits)
    frag_offset[20:22]; (13-bits)
    TTL[22]; (1-byte)
    Protocol[23]; (1-byte; ICMP==1, TCP==6, UDP==17,etc.)
    checksum[24:26]; (2-bytes)
    ip_src[26:30]; (4-bytes)
    ip_dst[30:34]; (4-bytes)
    options;
}

6. ICMP Structure
   (header is 4 bytes, plus 4 bytes for the specific type fields)
Read like:  struct.unpack('!BBH', curr_ip_header)
{
    type; (1-byte)
    code; (1-byte)
    checksum; (2-bytes)
    type_fields; (4-bytes)
    data; (n-bytes)
}
"""

import struct
import hashlib
import hw6test


class PacketProcessor:
    """
    Class created to process packets within PCAP files
    """

    def __init__(self):
        self.pcap_file = ''
        self.out_file = ''
        self.pcap_info = ''
        self._GLOBAL_PCAP_HEADER_SIZE = 24
        self._PACKET_HEADER_SIZE = 16
        self._ETH_HEADER_SIZE = 14
        self._IP_HEADER_SIZE = 20
        self._ICMP_HEADER_SIZE = 8
        self._PROTO_ICMP = 1
        self._BAD_HASH = 'B97D6CFCE32659677B4B801CAA1754B8'
        self.current_packet_count = 1
        self.icmp_write_count = 0
        self.pcap_info = {}

    @staticmethod
    def hash_data_upper(data):
        """
        Returns MD5 hash of provided data
        :param data:
        :return MD5 in upper case:
        """

        return hashlib.md5(data).hexdigest().upper()

    @staticmethod
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

    def set_out_file(self, file_to_open):
        """
        Prompts a user for a file to write the packet data to
        """
        out_file = ''

        try:
            out_file = open(file_to_open, 'w+')
        except FileNotFoundError:
            print("Sorry, {0} does not exist".format(file_to_open))
            exit(1)

        self.out_file = out_file

    def set_pcap_file(self, file_to_open):
        """
        Function used to open a pcap file for reading.
        Will check to see if provided file is a pcap based on
        magic value.
        """
        pcap_file = ''

        try:
            pcap_file = open(file_to_open, 'rb')

            if not self.is_pcap(pcap_file.read(4)):
                print("[{0}] is not a PCAP file!".format(pcap_file.name))
                exit(1)
            else:
                pcap_file.seek(0)
        except FileNotFoundError:
            print("Sorry, [{0}] does not exist".format(file_to_open))
            exit(1)

        self.pcap_file = pcap_file

    def process_icmp_data(self):
        """
        Takes in a pcap file to parse for ICMP data that doesn't have an
        MD5 of B97D6CFCE32659677B4B801CAA1754B8. Will write the ICMP data
        to outfile
        :return:
        """

        print("{0} Processing [ {1} ] {0}\n"
              .format('-'*20, self.pcap_file.name))

        try:
            # Seek to first packet header
            self.pcap_file.seek(self._GLOBAL_PCAP_HEADER_SIZE)

            # Read through the PCAP file until we reach EOF
            while True:
                # Read packet header, and unpack using a Struct format
                curr_packet_header = \
                    struct.unpack(
                        '<IIII', self.pcap_file.read(self._PACKET_HEADER_SIZE)
                    )

                # Capture the packet len and discovered offset
                packet_len = curr_packet_header[3]
                packet_offset = self.pcap_file.tell()
                end_of_curr_packet = packet_offset + packet_len

                # Check to see if the packet contains an ICMP header and data
                struct.unpack(
                    '<6s6sH', self.pcap_file.read(self._ETH_HEADER_SIZE)
                )

                # Based on the assumption that curr_eth_header == 8 (IPv4)
                # Read in the IP header (5*32bits == 20 bytes)
                # Fields to note are:
                #   curr_ip_header[2] == total length
                #   curr_ip_header[6] == protocol type
                curr_ip_header = struct\
                    .unpack('!BBHHHBBH4s4s', self.pcap_file
                            .read(self._IP_HEADER_SIZE))

                if curr_ip_header[6] == self._PROTO_ICMP:
                    struct.unpack(
                        '!BBHHH', self.pcap_file.read(self._ICMP_HEADER_SIZE)
                    )

                    # icmp data size would be:
                    icmp_data_len = packet_len - self._ETH_HEADER_SIZE \
                        - self._IP_HEADER_SIZE \
                        - self._ICMP_HEADER_SIZE

                    icmp_data = self.pcap_file.read(icmp_data_len)

                    if not (self.hash_data_upper(icmp_data) == self._BAD_HASH):
                        out_string_1 = "{2} ICMP Data Found at Packet# " \
                                       "{0} with data_len of {1} {2}\n"\
                            .format(
                                self.current_packet_count,
                                icmp_data_len, '-'*20
                            )

                        # Write the key data to a file
                        self.out_file.write(out_string_1)
                        self.out_file.write(str(icmp_data)+"\n\n")
                        self.icmp_write_count += 1
                else:
                    # Seek to the end of the
                    # current packet so we can read in the next
                    self.pcap_file.seek(end_of_curr_packet)

                self.pcap_info[self.current_packet_count] = \
                    [packet_offset, packet_len]

                # increment the current packet count
                self.current_packet_count += 1

        # Expect to throw at struct.error when we've reached EOF
        # pcap_file.read(n) should produce an empty string at EOF
        except struct.error:
            return
        except Exception as e:
            print("Sorry, an error occurred: ")
            print("\t {0}".format(e))
            exit(1)

    def print_pcap_info(self):
        """
        Prints metadata collected about the processed PCAP file
        :param pcap_info:
        :return none:
        """

        for packet, metadata in self.pcap_info.items():
            print("Processed Packet# {0} at Offset {1} of Size {2}"
                  .format(packet, metadata[0], metadata[1]))

        # Print number of ICMP packets processed
        print("\n{2} {0} key ICMP data packet(s) were written to [{1}] {2}"
              .format(self.icmp_write_count, self.out_file.name, '-' * 20))

    def close_files(self):
        """
        Method used to close the pcap and output files of
        the processor
        :return none:
        """
        self.pcap_file.close()
        self.out_file.close()

    @staticmethod
    def main():
        """
        Main routine where processing occurs (i.e. prompt user,
        read and process file, etc.)
        """

        # Collect Input and Output files
        print("{0} HW6:  rgully4's PCAP Processing Script {0}".format('-'*20))
        hw6_processor = PacketProcessor()
        hw6_processor.set_pcap_file(
            input("Please provide full path to PCAP to process: "))
        hw6_processor.set_out_file(
            input("Please provide full path to an output file: "))

        # Process the provided PCAP file for ICMP data
        hw6_processor.process_icmp_data()

        # Close PCAP and Output files
        hw6_processor.close_files()

        # Write PCAP Processing info to the console
        hw6_processor.print_pcap_info()


if __name__ == '__main__':
    # Run the PacketProcessor main routine
    PacketProcessor.main()

    # Run tests within the hw6test module
    hw6test.HW6Test.main()
