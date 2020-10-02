# CFRS 772 - Homework 3
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# Description:
#   This is the updated version of the gameclasses.py file from the
#   'Learn Python in a Day' book. The updates include PEP8 compliance
#   and the addition of code to support the 'HexGame'.


class Game:
    def __init__(self, num_of_questions=0):
        self._num_of_questions = num_of_questions

    @property
    def num_of_questions(self):
        return self._num_of_questions

    @num_of_questions.setter
    def num_of_questions(self, value):
        if value < 1:
            self._num_of_questions = 1
            print("\nMinimum Number of Questions = 1")
            print("Hence, number of questions will be set to 1")
        elif value > 10:
            self._num_of_questions = 10
            print("\nMaximum Number of Questions = 10")
            print("Hence, number of questions will be set to 10")
        else:
            self._num_of_questions = value


# New class HexGame for user to convert integers to hex values
class HexGame(Game):
    def generate_questions(self):
        from random import randint
        score = 0

        for i in range(self.num_of_questions):
            base10 = randint(1, 100)
            user_result = input("\nPlease convert {0} to hex: ".format(base10))

            while True:
                try:
                    answer = int(user_result, base=16)
                    if answer == base10:
                        print("Correct Answer!")
                        score = score + 1
                        break
                    else:
                        print("Wrong answer." \
                            "The correct answer is {:x}.".format(base10))
                        break
                except ValueError:
                    print("You did not enter a hex number. Please try again.")
                    user_result = \
                        input("\nPlease convert {0} to hex: ".format(base10))
        return score


class BinaryGame(Game):
    def generate_questions(self):
        from random import randint
        score = 0

        for i in range(self.num_of_questions):
            base10 = randint(1, 100)
            user_result = \
                input("\nPlease convert {0} to binary: ".format(base10))
            while True:
                try:
                    answer = int(user_result, base=2)
                    if answer == base10:
                        print("Correct Answer!")
                        score = score + 1
                        break
                    else:
                        print("Wrong answer. "
                              "The correct answer is {:b}.".format(base10))
                        break
                except ValueError:
                    print("You did not enter a binary number. "
                          "Please try again.")
                    user_result = \
                        input("\nPlease convert "
                              "{0} to binary: ".format(base10))
        return score


class MathGame(Game):
    def generate_questions(self):
        from random import randint
        score = 0
        number_list = [0, 0, 0, 0, 0]
        symbol_list = ['', '', '', '']
        operator_dict = {1: ' + ', 2: ' - ', 3: '*', 4: '**'}

        for i in range(self.num_of_questions):
            for index in range(0, 5):
                number_list[index] = randint(1, 9)

            # refer to explanation below
            for index in range(0, 4):
                if index > 0 and symbol_list[index - 1] == '**':
                    symbol_list[index] = operator_dict[randint(1, 3)]
                else:
                    symbol_list[index] = operator_dict[randint(1, 4)]

            questions_string = str(number_list[0])

            for index in range(0, 4):
                questions_string = questions_string + \
                                   symbol_list[index] + \
                                   str(number_list[index+1])

            result = eval(questions_string)

            questions_string = questions_string.replace("**", "^")

            user_result = input(
                "\nPlease evaluate {0}: ".format(questions_string))

            while True:
                try:
                    answer = int(user_result)
                    if answer is result:
                        print("Correct Answer!")
                        score = score + 1
                        break
                    else:
                        print("Wrong answer. "
                              "The correct answer is {:d}.".format(result))
                        break
                except ValueError:
                    print("You did not enter a valid number. "
                          "Please try again.")
                    user_result = \
                        input("\nPlease evaluate {0}: "
                              "".format(questions_string))
        return score


'''
Explanation:

Starting from the second item (i.e. index = 1) in symbol_list,
the line if index > 0 and symbol_list[index-1] == '**':
checks if the previous item in symbol_list is the ** symbol..

If it is, the statement
symbol_list[index] = operator_dict[randint(1, 3)] will execute.
In this case, the range given to the randint function is from 1 to 3.
Hence, the ** symbol, which has a key of 4 in operator_dict
will NOT be  assigned to symbol_list[index].

On the other hand, if it is not, the statement
symbol_list[index] = operator_dict[randint(1, 4)] will execute.
Since the range given to the randint function is 1 to 4,
the numbers 1, 2, 3 or 4 will be generated.
Hence, the symbols +, -, * or ** will be
assigned to symbol_list[index].
'''
