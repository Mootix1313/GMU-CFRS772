# CFRS 772 - Homework 6
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# Description:
#   This module serves as a unittest suite for HW6 functionality
#   The hw6 module is the baseline being tested. The test suite will
#   check the contents of the outfile produced by hw6
#
# MD5 hashes of referenced/sample files
#   hw6_test_out:   14c40a13d7453b1a7a202aa45239a4ff
#   HW6data.pcap:   facf57663c2efd966a6e63292ed77675
#
# References:
#   https://kite.com/python/examples/1293/unittest-add-test-cases-to-a-test-suite
#   https://docs.python.org/3/library/unittest.html
#   https://stackoverflow.com/questions/12011091/trying-to-implement-python-testsuite

import unittest
import hashlib
from hw6 import PacketProcessor


class HW6Test(unittest.TestCase):
    """
    Class used to test the functionality of the hw6 module
    """

    def test_file_open(self):
        """
        Testing that hw6.PacketProcessor can handle file
        error
        :return:
        """

        print("[-- Test: 'Opening Files' --]\n")

        bad_filename = "blahblahblah"
        not_pcap = "HW6.pdf"
        test_processor = PacketProcessor()

        # PacketProcessor should handle unknown files correctly
        with self.assertRaises(SystemExit):
            test_processor.set_pcap_file(bad_filename)

        with self.assertRaises(SystemExit):
            test_processor.set_pcap_file(not_pcap)

    def test_processing_and_output(self):
        """
        Making sure the output file results in the expected output
        Compares the hash of a known good to an output file generated
        :return:
        """
        print("\n[-- Test: 'Processing and Output' --]\n")

        # Set up variables
        known_good_hash = '14c40a13d7453b1a7a202aa45239a4ff'.upper()
        exemplar_pcap = 'HW6data.pcap'
        test_outfile = 'hw6_test_out'
        test_processor = PacketProcessor()
        test_md5 = hashlib.md5()
        read_chunk = 4096
        tot_packets = 61

        # Process the exemplar PCAP and capture the output
        test_processor.set_pcap_file(exemplar_pcap)
        test_processor.set_out_file(test_outfile)
        test_processor.process_icmp_data()
        test_processor.close_files()

        # Calculate the MD5 hash of hw6_test_output
        with open(test_outfile, 'rb') as f:
            while True:
                data = f.read(read_chunk)
                if not data:
                    break
                test_md5.update(data)
            f.close()

        # Make sure the known good matches the newly created outfile
        self.assertEqual(str(test_md5.hexdigest()).upper(), known_good_hash)

        # Make sure the number of packets
        #   processed matches the total number packets in
        #   the exemplar
        self.assertEqual(len(test_processor.pcap_info), tot_packets)

    @staticmethod
    def test_suite():
        my_suite = unittest.TestSuite()
        my_suite.addTest(unittest.makeSuite(HW6Test))
        return my_suite

    @staticmethod
    def main():
        print("\n{0} Running HW6 Test Suite {0}\n".format('-'*20))
        my_test = HW6Test.test_suite()
        runner = unittest.TextTestRunner()
        runner.run(my_test)
