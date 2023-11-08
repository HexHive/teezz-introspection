import unittest
import os
from clang.cindex import CursorKind, TypeKind, Diagnostic
from ast_traversal import ASTTraversal


DIR = os.path.dirname(os.path.abspath(__file__))
DATADIR = os.path.join(DIR, "data")

class TestFindHALCursor(unittest.TestCase):

    def test_find_c_hal_cursor(self):
        at = ASTTraversal(os.path.join(DATADIR, "c_hal.h"))
        cursor = at.find_hal_cursor("mystruct")
        assert cursor.kind == CursorKind.STRUCT_DECL
        assert cursor.spelling == "mystruct"

    def test_find_cpp_struct_hal_cursor(self):
        at = ASTTraversal(os.path.join(DATADIR, "cpp_hal.hpp"))
        cursor = at.find_hal_cursor("MyStruct")
        assert cursor.kind == CursorKind.STRUCT_DECL
        assert cursor.spelling == "MyStruct"

    def test_find_cpp_class_hal_cursor(self):
        at = ASTTraversal(os.path.join(DATADIR, "cpp_class_hal.hpp"))
        cursor = at.find_hal_cursor("MyHAL")
        assert cursor.kind == CursorKind.CLASS_DECL
        assert cursor.spelling == "MyHAL"

    def test_find_cpp_inner_class_cursor(self):
        at = ASTTraversal(os.path.join(DATADIR, "cpp_inner_class_hal.hpp"))
        cursor = at.find_hal_cursor("InnerStruct2")
        assert cursor.kind == CursorKind.STRUCT_DECL
        assert cursor.spelling == "InnerStruct2"

    def test_find_cpp_inner_struct_hal_cursor(self):
        at = ASTTraversal(os.path.join(DATADIR, "cpp_class_complex.hpp"))
        cursor = at.find_hal_cursor("InnerStruct")
        assert cursor.kind == CursorKind.STRUCT_DECL
        assert cursor.spelling == "InnerStruct"

    def test_find_typedef_struct(self):
        at = ASTTraversal(os.path.join(DATADIR, "cpp_hal_typedef.hpp"))
        cursor = at.find_hal_cursor("SomeStruct")
        assert cursor.kind == CursorKind.STRUCT_DECL
        assert cursor.spelling == "SomeStruct"

    def test_find_template_class_cursor(self):
        at = ASTTraversal(os.path.join(DATADIR, "cpp_class_template_small.hpp"))
        cursor = at.find_hal_cursor("MyTemplate")
        #at.print_ast(tu.cursor)
        assert cursor.kind == CursorKind.CLASS_TEMPLATE
        assert cursor.spelling == "MyTemplate"

    def test_find_cpp_internal_class_cursor(self):
        at = ASTTraversal(os.path.join(DATADIR, "cpp_class_hal_complex.hpp"))
        cursor = at.find_hal_cursor("InternalClass1")
        assert cursor.kind == CursorKind.CLASS_DECL
        assert cursor.spelling == "InternalClass1"

    def test_find_cpp_class_struct_cursor(self):
        at = ASTTraversal(os.path.join(DATADIR, "cpp_class_struct.hpp"))
        cursor = at.find_hal_cursor("InternalClass1")
        assert cursor.kind == CursorKind.CLASS_DECL
        assert cursor.spelling == "InternalClass1"

if __name__ == '__main__':
    unittest.main()
