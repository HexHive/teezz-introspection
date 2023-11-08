import argparse
import sys
import logging
from . import ioctldumper

################################################################################
# LOGGING
################################################################################

FORMAT = (
    "%(asctime)s,%(msecs)d %(levelname)-8s "
    "[%(filename)s:%(lineno)d] %(message)s"
)
logging.basicConfig(
    stream=sys.stdout,
    format=FORMAT,
    datefmt="%Y-%m-%d:%H:%M:%S",
    level=logging.DEBUG,
)
log = logging.getLogger(__name__)

################################################################################
# CODE
################################################################################

def setup_args():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "tee", help="Trusted execution environment we are targeting."
    )
    parser.add_argument(
        "ca",
        help="Client application hooked to observe interaction"
        " with trusted application.",
    )
    parser.add_argument("out_dir", help="Output directory for recordings.")
    return parser


if __name__ == "__main__":
    arg_parser = setup_args()
    args = arg_parser.parse_args()
    ioctldumper.main(args.tee, args.ca, args.out_dir)

