#!/usr/bin/env python
from __future__ import print_function
import sys
import os
import logging
import jsbeautifier
import json

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

FPTR_PREFIX = "fptr_"


def get_helpers():
    out = ""
    out += """
function isInArray(value, array) {
  return array.indexOf(value) > -1;
}

function arrayToInt(array) {
  var byteArray = new Uint8Array(array);
  var result = 0;
  for (var i = byteArray.length-1; i>=0; i--) {
    result *= 256;
    result += byteArray[i];
  }
  return result;
}

function mergeUint8Arrays(buf1, buf2) {
    var tmp = new Uint8Array(buf1.byteLength + buf2.byteLength);
    tmp.set(buf1, 0);
    tmp.set(buf2, buf1.byteLength);
    return tmp;
}

function smallIntToArray(num, sz_in_bytes) {
    // can only convert sz_in_bytes <= 4
    var byteArray = new Uint8Array(sz_in_bytes);
    for (var i = 0; i < sz_in_bytes; i++) {
        byteArray[i] = num & 0xff;
        num = num >> 8;
    }
    return byteArray;
}

function intToArray(num, sz_in_bytes) {
    if (sz_in_bytes < 8) {
        return smallIntToArray(num, sz_in_bytes);
    } else if (sz_in_bytes == 8) {
        // we assume num to be a NativePointer
        var bottom_half_val = num.and(uint64(0xffffffff));
        var bottom_half_arr = smallIntToArray(bottom_half_val, 4);
        var top_half_val = num.shr(uint64(32));
        var top_half_arr = smallIntToArray(top_half_val, 4);
        return mergeUint8Arrays(bottom_half_arr, top_half_arr);
    } else {
        console.log("Error: cannot handle sz_in_bytes " + sz_in_bytes);
        return null;
    }
}
    """
    return out


def get_module_init_code(module_name):
    module_init_code = """
var module_name = "{}";
var module = Process.findModuleByName(module_name);
var module_base = parseInt(module["base"], 16);
var DUMP_ID = 0; // can be used to identify calls to interceptor

""".format(
        module_name
    )
    return module_init_code


def get_fptr_code_offset(func_name, func_offset):
    """Returns js code for getting a frida handle to the function offset."""
    out = "var {}{} = ptr(module_base + {});\n".format(
        FPTR_PREFIX, func_name, func_offset
    )
    out += "var {}{}__hidl_cb = null;\n".format(FPTR_PREFIX, func_name)
    return out


def get_fptr_code_symbol(func_name, func_symbol):
    """Returns js code for getting a frida handle to the function symbol."""
    return "var {}{} = Module.getExportByName(module_name, '{}');\n".format(
        FPTR_PREFIX, func_name, func_symbol
    )


def get_fptr_cb_code(func_name):
    """Returns js code for storing a frida hook. Necessary for detaching the hook."""
    return "var {}{}_cb__hidl_cb = null;\n".format(FPTR_PREFIX, func_name)


def get_interceptor_code(func_name):
    interceptor_code = """
Interceptor.attach({0}{1}, {{
    onEnter: function (args) {{
        console.log("onEnter: {1}()");
        this.dump_id = DUMP_ID;
        this.args = new Array();
        send({{ 'lvl': 'high', 'type' : 'open_func_ctx', 'func' : '{1}', 'dump_id': this.dump_id }});
        dump("{1}", args, this.args, null, this.dump_id);
    }}, onLeave: function(ret) {{
        console.log("onLeave: {1}()");
        dump("{1}", this.args, null, ret, this.dump_id);
        send({{ 'lvl': 'high','type' : 'close_func_ctx', 'func' : '{1}', 'dump_id': this.dump_id }});
        DUMP_ID += 1;
    }}
}});
""".format(
        FPTR_PREFIX, func_name
    )
    return interceptor_code


def main(json_path):

    with open(json_path) as f:
        hal_module = json.load(f)

    out = ""
    out += "// generated based on {}\n\n".format(json_path)
    out += get_helpers()
    out += get_module_init_code(hal_module["name"])

    # add fptrs
    for name, f in hal_module["functions"].items():
        if "is_deprecated" in f:
            out += "// deprecated\n"
            out += "//"
        if "offset" in f.keys():
            out += get_fptr_code_offset(name, f["offset"])
        elif "symbol" in f.keys():
            out += get_fptr_code_symbol(name, f["symbol"])
            out += get_fptr_cb_code(name)
        else:
            print(f"No symbol or offset found for {name}.")
            return

    # add interceptors
    for name, f in hal_module["functions"].items():
        if "is_deprecated" in f:
            out += "\n// deprecated\n"
            out += "/*"
            out += get_interceptor_code(name)
            out += "*/\n"
        else:
            out += get_interceptor_code(name)

    print(jsbeautifier.beautify(out))


def usage():
    print("{} ./hal_description.json".format(sys.argv[0]))
    print("E.g.:")
    print(
        """
{
  "name" : "keystore.hi6250.so",
  "functions" : [
    "close" : { "offset" : "0x2E80" },
    "generate_keypair" : { "offset" : "0x2C80", "is_deprecated" : true },
    "verify_data" : { "offset" : "0x2530", "is_deprecated" : true },
    "get_supported_block_modes" : { "offset" : "0x3510" },
    "update" : { "offset" : "0x3A18" },
    "generate_key" : { "offset" : "0x498C" },
  ]
}
"""
    )


if __name__ == "__main__":
    if len(sys.argv) < 2 or not os.path.isfile(sys.argv[1]):
        usage()
        sys.exit(1)
    main(sys.argv[1])
