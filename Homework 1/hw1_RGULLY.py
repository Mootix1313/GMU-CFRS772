# CFRS 772 - Homework 1
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# import pdb
# pdb.set_trace()


def add(value1, value2):
    """
    This function returns value1 + value2
    :param value1:
    :param value2:
    :return:
    """
    try:
        return int(value1) + int(value2)
    except Exception as e:
        print("An error has occurred: " + str(e.__class__.__name__) +
              ". Please enter new numbers.")


def subtract(value1, value2):
    """
    This function returns value1 - value2
    :param value1:
    :param value2:
    :return value1-value2:
    """
    try:
        return int(value1) - int(value2)
    except Exception as e:
        print("An error has occurred: " + str(e.__class__.__name__) +
              ". Please enter new numbers.")


if __name__ == '__main__':
    # Prompting user for 3 values: n1, n2, and operation
    n1 = input("Please enter first number: ")
    n2 = input("Please enter second number: ")
    op = input("Please enter desired operation (add/subtract): ")

    # Check user's desired operation and call the appropriate function.
    if 'add' in op:
        result = add(n1, n2)
        if result is not None:
            print('Result: {0}'.format(result))
    elif 'subtract' in op:
        result = subtract(n1, n2)
        if result is not None:
            print('Result: {0}'.format(result))
    else:
        print("Operation not recognized.")
