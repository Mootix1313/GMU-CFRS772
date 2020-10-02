# CFRS 772 - Homework 3
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# Description:
#   This is the updated version of the gametasks.py file from the
#   'Learn Python in a Day' book. The updates include PEP8 compliance
#   and the addition of code to support the 'HexGame'.


def print_instructions(instruction):
    print(instruction)


def get_user_score(user_name):
    try:
        user_input = open('userScores.txt', 'r')
        for line in user_input:
            content = line.split(', ')
            if content[0] == user_name:
                user_input.close()
                return content[1]
        user_input.close()
        return '-1'
    except IOError:
        print("File not found. A new file will be created.")
        user_input = open('userScores.txt', 'w')
        user_input.close()
        return '-1'


def update_user_score(new_user, user_name, score):
    from os import remove, rename

    if new_user is True:
        user_input = open('userScores.txt', 'a')
        user_input.write(user_name + ', ' + score + '\n')
        user_input.close()
    else:
        temp = open('userScores.tmp', 'w')
        user_input = open('userScores.txt', 'r')
        for line in user_input:
            content = line.split(', ')
            if content[0] == user_name:
                temp.write(user_name + ', ' + score + '\n')
            else:
                temp.write(line)

        user_input.close()
        temp.close()
        remove('userScores.txt')
        rename('userScores.tmp', 'userScores.txt')
