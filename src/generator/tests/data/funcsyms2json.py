#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import re
import cxxfilt

FUNCS = "myfuncptr2\|simple_func\|func_a\|ints\|floats\|func_b\|myfunc\|myfuncptr\|longs\|bytes\|class_ptr\|shorts\|myfunc_a\|class_arg\|bools\|doubles\|func_c"

BLACKLIST_KEYWORDS = ["GLOBAL"]
BLACKLIST = re.compile(
    "|".join([re.escape(word) for word in BLACKLIST_KEYWORDS])
)


def main(binary_path, is_cpp):
    binary_name = os.path.basename(binary_path)
    CMD = """nm -s {} | grep '{}' | awk -F " " '{{ printf "%s:%s\\n", $3, $1 }}'""".format(
        binary_path, FUNCS
    )
    proc = subprocess.Popen(CMD, shell=True, stdout=subprocess.PIPE)
    out, _ = proc.communicate()
    lines = out.decode().split("\n")

    # filter lines for blacklisted keywords
    lines = [line for line in lines if not BLACKLIST.search(line) and line]

    funcs = {}
    for line in lines:
        fname, addr = line.split(":")
        addr = f"0x{addr}"
        if is_cpp:
            # there is probably some weird cpp feature that we did not think of here
            # let's use it until it breaks...
            func = cxxfilt.demangle(fname)
            idx = func.find("(")
            fname = func[:idx].split("::")[-1]
        funcs[fname] = {"offset": addr}

    data = {"name": binary_name, "functions": funcs}

    print(json.dumps(data))


def usage():
    print(f"{sys.argv[0]} /path/to/binary")


if __name__ == "__main__":
    if len(sys.argv) < 2 or not os.path.isfile(sys.argv[1]):
        usage()
        sys.exit()

    binary_path = sys.argv[1]
    is_cpp = True if os.path.basename(binary_path).startswith("cpp") else False
    main(binary_path, is_cpp)
