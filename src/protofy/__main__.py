import sys
import logging
from .protofy import Protofy


logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def usage():
    def_spelling = '"struct keymaster1_device"'
    tu_path = "./libhardware/include/hardware/keymaster1.h"
    clang_args = "-I./libhardware/include/ -I./core/libcutils/include/ -I./core/libsystem/include/"
    print(f"Usage:\n\t{sys.argv[0]} {def_spelling} {tu_path} {clang_args}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()
        sys.exit()

    p = Protofy(sys.argv[1], sys.argv[2], sys.argv[3:])
