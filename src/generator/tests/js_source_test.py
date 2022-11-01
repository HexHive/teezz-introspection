import unittest
import re
import os
from clang.cindex import CursorKind, TypeKind, Diagnostic
from generator import gendumper
from pyjsparser import parse
from pprint import pprint


DIR = os.path.dirname(os.path.abspath(__file__))
DATADIR = os.path.join(DIR, "data")


class TestHooksExist(unittest.TestCase):

    TEST_SOURCE_FILENAME = "c_hal.h"
    CURSOR_SPELLING = "mystruct"
    CLANG_ARGS = ["-x", "c", "-Wall"]

    def setUp(self):
        tu_path = os.path.join(DATADIR, TestHooksExist.TEST_SOURCE_FILENAME)
        tu = gendumper.parse(tu_path, TestHooksExist.CLANG_ARGS)
        assert tu is not None, "generating tu failed"

        # find the cursor we are looking for
        cursor = gendumper.find_hal_cursor(tu.cursor, TestHooksExist.CURSOR_SPELLING)
        assert tu, "could not find cursor"

        self.js = gendumper.emit_js(cursor)
        self.parsed_js = parse(self.js)

    def test_functions_exist(self):
        # we are only interested in top-level function declarations
        func_decls = [node for node in self.parsed_js['body'] if node['type'] == 'FunctionDeclaration']
        assert len(func_decls) == 4, f"Generated functions incomplete. Should be 4, got {len(func_decls)}"

        expected_funcs = ["dump_myfunc_a", "dump_myfunc_b", "dump_myfunc_ret", "dump"]
        for func_decl in func_decls:
            if func_decl['id']['name'] in expected_funcs:
                expected_funcs.remove(func_decl['id']['name'])
        assert len(expected_funcs) == 0, f"Generated functions incomplete." \
                "Following functions are missing: {expected_funcs}"

    def test_first_parameter_dumping_logic(self):
        # we are only interested in top-level function declarations
        func_decls = [node for node in self.parsed_js['body'] if node['type'] == 'FunctionDeclaration']
        for func_decl in func_decls:
            if func_decl['id']['name'] == "dump_myfunc_a":
                first_func = func_decl 
        assert first_func, "Could not find dump_func_a"
        body = first_func['body']

        # TODO: (1) we expect arg to be stored in a variable
        # TODO: (2) we expect this variable to be send to the host
        # TODO: check if type (`int`) properly extracted from memory and sent to host
        import ipdb; ipdb.set_trace()


if __name__ == '__main__':
    unittest.main()

