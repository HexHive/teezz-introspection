import sys
import os
import logging


# from .protofycpp import ProtofyCPP
from .gendumper import IntrospectionRecorderGenerator

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def usage():
    print("{} <struct_name> <header_file> [<clang_options>]".format(sys.argv[0]))
    print("\nE.g.:")
    print('\t{} "struct keymaster1_device" km.hpp'.format(sys.argv[0]))
    print('\t{} "struct gatekeeper_device" gk.hpp'.format(sys.argv[0]))
    print('\t{} "struct fingerprint_device" fp.hpp'.format(sys.argv[0]))


if __name__ == "__main__":

    if len(sys.argv) < 3:
        usage()
        sys.exit(1)

    if not os.path.isfile(sys.argv[2]):
        print(f"File {sys.argv[2]} not found")
        sys.exit(1)

    irg = IntrospectionRecorderGenerator(sys.argv[1], sys.argv[2], sys.argv[3:])
    print(irg.recorders2str())
