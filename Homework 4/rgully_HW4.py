# CFRS 772 - Homework 4
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# Description:
#   This project serves as a unittest suite for HW2 functionality
#   The hw2_jones_key_final module is the baseline being tested
#   Each function will have three test cases testing their ability
#       to correctly find a key word in a text or binary file
#
# MD5 hashes of referenced/sample files
#   hw2_jones_key_final:    6bd840110b5ca82c502a8dcd97daccf9
#   sample_binary.jpg:      4314ab1831e4bbf492a58717ced26663
#   sample_partial.txt:     84eaf428ce5ea3b0832291b90e3f6353
#
# References:
#   https://kite.com/python/examples/1293/unittest-add-test-cases-to-a-test-suite
#   https://docs.python.org/3/library/unittest.html
#   https://stackoverflow.com/questions/12011091/trying-to-implement-python-testsuite

import unittest
import hw2_jones_key_final


class MyTest(unittest.TestCase):
    """
    Class used to test the functionality of hw2_jones_key_final
    """

    def test_TextFile(self):
        """
        Unit test for verifying some of TextFile's functionality
        """

        # Can the findSearchTerm method correctly locate the sequence provided?
        self.assertEqual(
            (hw2_jones_key_final.TextFile("sample_partial.txt"))
            .findSearchTerm("Python"), [18, 61, 278, 313, 878]
        )

        # Can the findSearchTerm method correctly locate the sequence provided?
        self.assertEqual(
            (hw2_jones_key_final.TextFile("sample_partial.txt"))
            .findSearchTerm("Jones"), []
        )

        # Is the FileNotFoundError raised when
        # attempting to open a non-existent file?
        with self.assertRaises(FileNotFoundError):
            hw2_jones_key_final.TextFile("blahblahblah124.txt")\
                .findSearchTerm("module")

    def test_BinaryFile(self):
        """
        Unit test for verifying some of BinFile's functionality
        """

        # Can the findSearchTerm method correctly locate the sequence provided?
        self.assertEqual(
            (hw2_jones_key_final.BinFile("sample_binary.jpg"))
            .findSearchTerm("ff d9"), [37073]
        )

        # Can the findSearchTerm method correctly locate the sequence provided?
        self.assertEqual(
            (hw2_jones_key_final.BinFile("sample_binary.jpg"))
            .findSearchTerm("ff d8 ff e0"), [0]
        )

        # Does system exit upon receiving a non-hex pattern?
        with self.assertRaises(SystemExit):
            hw2_jones_key_final.BinFile("sample_binary.jpg")\
                .findSearchTerm(";alskdjf")

    @staticmethod
    def test_suite():
        """
        Creating a test suite for easily running all tests
        :return TestSuite object:
        """
        my_suite = unittest.TestSuite()
        my_suite.addTest(unittest.makeSuite(MyTest))
        return my_suite


if __name__ == '__main__':
    """
    Main routine for creating a test suite and running the tests
    """

    test_suite = MyTest.test_suite()
    runner = unittest.TextTestRunner()
    runner.run(test_suite)
