import os
import chaucha


def main():
    # my_input = os.environ["INPUT_MYINPUT"]

    # my_output = f"Hello {my_input}"

    # print(f"::set-output name=myOutput::{my_output}")
    print(chaucha.wallet.new())

if __name__ == "__main__":
    main()
