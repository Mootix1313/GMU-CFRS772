# CFRS 772 - Homework 3
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# Description:
#   This is the updated version of the project.py file from the
#   'Learn Python in a Day' book. The updates include PEP8 compliance
#   and the addition of code to support the 'HexGame'.


from gametasks import print_instructions, get_user_score, update_user_score
from gameclasses import MathGame, BinaryGame, HexGame

try:
    math_instructions = '''In this game, you will be given a simple arithmetic question.
    Each correct answer gives you one mark.
    No mark is deducted for wrong answers.'''

    binary_instructions = '''
    In this game, you will be given a number in base 10.
    Your task is to convert this number to base 2.
    Each correct answer gives you one mark.
    No mark is deducted for wrong answers.
    '''

    hex_instructions = '''
    In this game, you will be given a number in base 10.
    Your task is to convert this number to base 16.
    Each correct answer gives you one mark.
    No mark is deducted for wrong answers.
    '''

    mg = MathGame()
    bg = BinaryGame()
    hg = HexGame()

    userName = input("\nPlease enter your username: ")

    score = int(get_user_score(userName))

    if score == -1:
        newUser = True
        score = 0
    else:
        newUser = False

    print("\nHello {0}, welcome to the game.".format(userName))
    print("Your current score is {0}.".format(score))

    user_choice = 0

    while user_choice != '-1':
        game = input("\nMath Game (1), Binary Game (2), or Hex Game (3)?: ")
        while game != '1' and game != '2' and game != '3':
            print("You did not enter a valid choice. Please try again.")
            game = input("\nMath Game (1),"
                         " Binary Game (2),"
                         " or Hex Game (3)?: ")

        numPrompt = input("\nHow many questions do"
                          " you want per game (1 to 10)?: ")
        while True:
            try:
                num = int(numPrompt)
                break
            except ValueError:
                print("You did not enter a valid number. Please try again.")
                numPrompt = input("\nHow many questions do "
                                  "you want per game (1 to 10)?: ")

        if game == '1':
            mg.num_of_questions = num
            print_instructions(math_instructions)
            score = score + mg.generate_questions()
        elif game == '2':
            bg.num_of_questions = num
            print_instructions(binary_instructions)
            score = score + bg.generate_questions()

        # Additional code to accommodate the Hex Game
        else:
            hg.num_of_questions = num
            print_instructions(hex_instructions)
            score = score + hg.generate_questions()

        print("\nYour current score is {0}.".format(score))

        user_choice = input("\nPress Enter to continue or -1 to end: ")

    update_user_score(newUser, userName, str(score))

except Exception as e:
    print("An unknown error occurred. Program will exit.")
    print("Error: ", e)
