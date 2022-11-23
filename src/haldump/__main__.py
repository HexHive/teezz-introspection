import sys
from . import dump


def usage():
    print(
        "{0} <daemon> <dumper.js>\n\ne.g.\n\t{0} keystore keystore_hal_msm8922_gen.js".format(
            sys.argv[0]
        )
    )


if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()
        sys.exit()
    dump.main(sys.argv[1], sys.argv[2])
