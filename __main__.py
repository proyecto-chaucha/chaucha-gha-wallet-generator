import os
import sys
import chaucha


def main():

    arg = ""

    try:
        arg = sys.argv[1]
    except BaseException:
        pass

    value = os.getenv("INPUT_VALUE") or arg
    privkey, pubkey = chaucha.wallet.new(value)

    print(f"::set-output name=privkey::{privkey}")
    print(f"::set-output name=pubkey::{pubkey}")


if __name__ == "__main__":
    main()
