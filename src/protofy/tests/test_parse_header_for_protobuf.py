import os
import unittest
import subprocess
from clang.cindex import CursorKind, TypeKind
from protofycpp import ProtofyCPP

DIR = os.path.dirname(os.path.abspath(__file__))
DATADIR = os.path.join(DIR, "data")
AOSPDIR = os.path.join(DATADIR, "aosp")
PROTOC = "protoc"


class TestParseHeaderProtobuf(unittest.TestCase):

    def _check_sizes(self, pr, enums, structs, reftypes, fptrs):
        assert len(pr.type_info['fptr']) == fptrs
        assert len(pr.type_info['enums']) == enums
        assert len(pr.type_info['structs']) == structs
        assert len(pr.type_info['reftypes']) == reftypes

    def test_parse_c_hal(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "c_hal.h"))
        cursor = pr.find_hal_cursor("mystruct")
        assert cursor.kind == CursorKind.STRUCT_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 0, 0, 1)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 2
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "c_hal.h"))
        pr.create_protobuf("mystruct")
        protoc_args = [PROTOC, "--python_out=.", "mystruct.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./mystruct.proto")
        os.remove("mystruct_pb2.py")

    def test_parse_c_hal_complex(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "c_hal_complex.hpp"))
        cursor = pr.find_hal_cursor("MyStruct")
        assert cursor.kind == CursorKind.STRUCT_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 3, 2, 2)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 2
        for struct in pr.type_info['structs']:
            assert len(pr.type_info['structs'][struct]['fields']) >= 2
            assert len(pr.type_info['structs'][struct]['fields']) <= 3
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "c_hal_complex.hpp"))
        pr.create_protobuf("MyStruct")
        protoc_args = [PROTOC, "--python_out=.", "MyStruct.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyStruct.proto")
        os.remove("MyStruct_pb2.py")

    def test_parse_cpp_primitive_types(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_primitive_types.hpp"))
        cursor = pr.find_hal_cursor("MyClass")
        assert cursor.kind == CursorKind.CLASS_DECL
        assert cursor.spelling == "MyClass"
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 2, 11, 7)
        func_list = [
            "bytes", "shorts", "ints", "longs", 
            "bools", "floats", "doubles",
        ]
        for fptr in pr.type_info['fptr']:
            assert fptr in func_list
        reftype_list = [
            "__int8_t_ref", "char_ref", "__int16_t_ref", "__uint16_t_ref",
            "int_ref", "uint32_t_ref", "long_ref", "__int64_t_ref",
            "bool_ref", "float_ref", "double_ref",
        ]
        for ref in pr.type_info['reftypes']:
            assert ref in reftype_list
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_primitive_types.hpp"))
        pr.create_protobuf("MyClass")
        protoc_args = [PROTOC, "--python_out=.", "MyClass.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyClass.proto")
        os.remove("MyClass_pb2.py")

    def test_parse_cpp_hal(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal.hpp"))
        cursor = pr.find_hal_cursor("MyStruct")
        assert cursor.kind == CursorKind.STRUCT_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 0, 0, 1)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 2
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal.hpp"))
        pr.create_protobuf("MyStruct")
        protoc_args = [PROTOC, "--python_out=.", "MyStruct.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyStruct.proto")
        os.remove("MyStruct_pb2.py")

    def test_parse_cpp_hal_typedef(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal_typedef.hpp"))
        cursor = pr.find_hal_cursor("MyStruct")
        assert cursor.kind == CursorKind.STRUCT_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 1, 1, 1)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 2
        for struct in pr.type_info['structs']:
            assert len(pr.type_info['structs'][struct]['fields']) == 3
            assert "SomeStruct_t" in struct
        for reftype in pr.type_info['reftypes']:
            assert "SomeStruct_t" in reftype
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal_typedef.hpp"))
        pr.create_protobuf("MyStruct")
        protoc_args = [PROTOC, "--python_out=.", "MyStruct.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyStruct.proto")
        os.remove("MyStruct_pb2.py")

    def test_parse_cpp_hal_enum(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal_enum.hpp"))
        cursor = pr.find_hal_cursor("MyStruct")
        assert cursor.kind == CursorKind.STRUCT_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 1, 0, 0, 1)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 2
        for enum in pr.type_info['enums']:
            assert len(pr.type_info['enums'][enum]) == 4
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal_enum.hpp"))
        pr.create_protobuf("MyStruct")
        protoc_args = [PROTOC, "--python_out=.", "MyStruct.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyStruct.proto")
        os.remove("MyStruct_pb2.py")

    def test_parse_cpp_hal_array(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal_array.hpp"))
        cursor = pr.find_hal_cursor("MyStruct")
        assert cursor.kind == CursorKind.STRUCT_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 1, 0, 2)
        for fptr in pr.type_info['fptr']:
            info = pr.type_info['fptr'][fptr]
            assert len(info) == 2
            if fptr == "func_b":
                assert info[0]['type_spelling'][0] == TypeKind.CONSTANTARRAY
        for struct in pr.type_info['structs']:
            assert len(pr.type_info['structs'][struct]['fields']) == 2
            for field in pr.type_info['structs'][struct]['fields']:
                assert field['type_spelling'][0] == TypeKind.CONSTANTARRAY
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal_array.hpp"))
        pr.create_protobuf("MyStruct")
        protoc_args = [PROTOC, "--python_out=.", "MyStruct.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyStruct.proto")
        os.remove("MyStruct_pb2.py")

    def test_parse_cpp_hal_callback(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal_callback.hpp"))
        cursor = pr.find_hal_cursor("MyStruct")
        assert cursor.kind == CursorKind.STRUCT_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        self._check_sizes(pr, 0, 0, 0, 1)
        for fptr in pr.type_info['fptr']:
            info = pr.type_info['fptr'][fptr]
            assert len(info) == 1
            assert info[0]['type_spelling'][0] == TypeKind.ULONG
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 0, 0, 1)
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal_callback.hpp"))
        pr.create_protobuf("MyStruct")
        protoc_args = [PROTOC, "--python_out=.", "MyStruct.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyStruct.proto")
        os.remove("MyStruct_pb2.py")

    def test_parse_cpp_hal_pointer(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal_pointer.hpp"))
        cursor = pr.find_hal_cursor("MyStruct")
        pr.hal_name = "MyStruct"
        assert cursor.kind == CursorKind.STRUCT_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 2, 7, 3)
        for fptr in pr.type_info['fptr']:
            info = pr.type_info['fptr'][fptr]
            assert len(info) == 2
            assert info[0]['type_spelling'][0] == TypeKind.VOID
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal_pointer.hpp"))
        pr.create_protobuf("MyStruct")
        protoc_args = [PROTOC, "--python_out=.", "MyStruct.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyStruct.proto")
        os.remove("MyStruct_pb2.py")

    def test_parse_cpp_hal_union(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal_union.hpp"))
        cursor = pr.find_hal_cursor("MyStruct")
        pr.hal_name = "MyStruct"
        assert cursor.kind == CursorKind.STRUCT_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 2, 1, 2)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 1
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal_union.hpp"))
        pr.create_protobuf("MyStruct")
        protoc_args = [PROTOC, "--python_out=.", "MyStruct.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyStruct.proto")
        os.remove("MyStruct_pb2.py")

    """
    def test_parse_cpp_hal_template(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal_template.hpp"))
        cursor = pr.find_hal_cursor("MyStruct")
        assert cursor.kind == CursorKind.STRUCT_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 2, ???, 3)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) >= 1
            assert len(pr.type_info['fptr'][fptr]) <= 2
        # TODO breaks here
        assert len(pr.type_info['structs']) >= 2
        # TODO reftypes??
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hal_template.hpp"))
        pr.create_protobuf("MyStruct")
        protoc_args = [PROTOC, "--python_out=.", "MyStruct.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyStruct.proto")
        os.remove("MyStruct_pb2.py")
    """

    def test_parse_cpp_class_hal(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_hal.hpp"))
        cursor = pr.find_hal_cursor("MyHAL")
        assert cursor.kind == CursorKind.CLASS_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 0, 0, 1)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 2
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_hal.hpp"))
        pr.create_protobuf("MyHAL")
        protoc_args = [PROTOC, "--python_out=.", "MyHAL.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyHAL.proto")
        os.remove("MyHAL_pb2.py")

    def test_parse_cpp_class_hal_extended(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_hal_extended.hpp"))
        cursor = pr.find_hal_cursor("MyHAL")
        assert cursor.kind == CursorKind.CLASS_DECL
        assert cursor.spelling == "MyHAL"
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 1, 1, 3)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) != 0
        for struct in pr.type_info['structs']:
            assert len(pr.type_info['structs'][struct]['fields']) == 2
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_hal_extended.hpp"))
        pr.create_protobuf("MyHAL")
        protoc_args = [PROTOC, "--python_out=.", "MyHAL.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyHAL.proto")
        os.remove("MyHAL_pb2.py")

    def test_parse_cpp_class_complex(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_complex.hpp"))
        cursor = pr.find_hal_cursor("MyHAL")
        assert cursor.kind == CursorKind.CLASS_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 3, 1, 1)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 1
        for struct in pr.type_info['structs']:
            assert len(pr.type_info['structs'][struct]['fields']) >= 2
            assert len(pr.type_info['structs'][struct]['fields']) <= 4
        for reftype in pr.type_info['reftypes']:
            assert "MyStruct" in reftype
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_complex.hpp"))
        pr.create_protobuf("MyHAL")
        protoc_args = [PROTOC, "--python_out=.", "MyHAL.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyHAL.proto")
        os.remove("MyHAL_pb2.py")

    def test_parse_cpp_class_template_small(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_template_small.hpp"))
        cursor = pr.find_hal_cursor("MyStruct")
        assert cursor.kind == CursorKind.STRUCT_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 1, 1, 1)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 1
        for struct in pr.type_info['structs']:
            assert len(pr.type_info['structs'][struct]['fields']) == 1
            assert "MyTemplate" in struct
            assert "int" in struct
        for reftype in pr.type_info['reftypes']:
            assert "MyTemplate" in reftype
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_template_small.hpp"))
        pr.create_protobuf("MyStruct")
        protoc_args = [PROTOC, "--python_out=.", "MyStruct.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyStruct.proto")
        os.remove("MyStruct_pb2.py")

    def test_parse_cpp_class_parameter(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_parameter.hpp"))
        cursor = pr.find_hal_cursor("MyStruct")
        assert cursor.kind == CursorKind.STRUCT_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 2, 1, 1)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 1
        for struct in pr.type_info['structs']:
            assert len(pr.type_info['structs'][struct]['fields']) == 2
        for reftype in pr.type_info['reftypes']:
            assert "MyClass" in reftype
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_parameter.hpp"))
        pr.create_protobuf("MyStruct")
        protoc_args = [PROTOC, "--python_out=.", "MyStruct.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyStruct.proto")
        os.remove("MyStruct_pb2.py")

    def test_parse_cpp_class_enum(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_enum.hpp"))
        cursor = pr.find_hal_cursor("MyHAL")
        assert cursor.kind == CursorKind.CLASS_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 1, 0, 0, 1)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 2
        for enum in pr.type_info['enums']:
            assert len(pr.type_info['enums'][enum]) == 5
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_enum.hpp"))
        pr.create_protobuf("MyHAL")
        protoc_args = [PROTOC, "--python_out=.", "MyHAL.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyHAL.proto")
        os.remove("MyHAL_pb2.py")

    def test_parse_cpp_class_struct(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_struct.hpp"))
        cursor = pr.find_hal_cursor("MyHAL")
        assert cursor.kind == CursorKind.CLASS_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 6, 6, 3)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 2
        for struct in pr.type_info['structs']:
            assert len(pr.type_info['structs'][struct]['fields']) >= 2
            assert len(pr.type_info['structs'][struct]['fields']) <= 3
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_struct.hpp"))
        pr.create_protobuf("MyHAL")
        protoc_args = [PROTOC, "--python_out=.", "MyHAL.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyHAL.proto")
        os.remove("MyHAL_pb2.py")

    def test_parse_cpp_class_hal_complex(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_hal_complex.hpp"))
        cursor = pr.find_hal_cursor("MyHAL")
        assert cursor.kind == CursorKind.CLASS_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 4, 6, 2)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 2
        for struct in pr.type_info['structs']:
            assert len(pr.type_info['structs'][struct]['fields']) == 2
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_hal_complex.hpp"))
        pr.create_protobuf("MyHAL")
        protoc_args = [PROTOC, "--python_out=.", "MyHAL.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyHAL.proto")
        os.remove("MyHAL_pb2.py")

    def test_parse_cpp_class_array(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_array.hpp"))
        cursor = pr.find_hal_cursor("MyHAL")
        assert cursor.kind == CursorKind.CLASS_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 3, 2, 3)
        for fptr in pr.type_info['fptr']:
            info = pr.type_info['fptr'][fptr]
            assert len(info) == 3
            assert info[0]['type_spelling'][0] == TypeKind.CONSTANTARRAY
            if fptr == "func_a":
                assert info[1]['type_spelling'][0] == TypeKind.CONSTANTARRAY
        for struct in pr.type_info['structs']:
            assert len(pr.type_info['structs'][struct]['fields']) == 2
            if struct != 'short':
                for field in pr.type_info['structs'][struct]['fields']:
                    assert field['type_spelling'][0] == TypeKind.CONSTANTARRAY
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_array.hpp"))
        pr.create_protobuf("MyHAL")
        protoc_args = [PROTOC, "--python_out=.", "MyHAL.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyHAL.proto")
        os.remove("MyHAL_pb2.py")

    def test_parse_cpp_class_callback(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_callback.hpp"))
        cursor = pr.find_hal_cursor("MyHAL")
        assert cursor.kind == CursorKind.CLASS_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        self._check_sizes(pr, 0, 2, 0, 3)
        for fptr in pr.type_info['fptr']:
            info = pr.type_info['fptr'][fptr]
            assert len(info) == 2
            if fptr == "func_b":
                assert info[0]['type_spelling'][0] == TypeKind.ULONG
            else:
                assert info[0]['type_spelling'][0] == TypeKind.RECORD
        for struct in pr.type_info['structs']:
            if struct == "CallbackClass":
                assert len(pr.type_info['structs'][struct]['fields']) == 0
            else:
                assert len(pr.type_info['structs'][struct]['fields']) == 1
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 1, 0, 3)
        for fptr in pr.type_info['fptr']:
            if fptr != "func_c":
                info = pr.type_info['fptr'][fptr]
                assert info[0]['type_spelling'][0] == TypeKind.ULONG
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_callback.hpp"))
        pr.create_protobuf("MyHAL")
        protoc_args = [PROTOC, "--python_out=.", "MyHAL.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyHAL.proto")
        os.remove("MyHAL_pb2.py")

    def test_parse_cpp_hidl_vec(self):
        # path to aosp/ needs to be set
        assert AOSPDIR is not None
        args_list = [
            "libhardware/include", "core/libsystem/include",
            "core/libcutils/include", "core/libutils/include",
            "", "libhidl/base/include", "libfmqbase",
        ]
        args_list = ["-I{}".format(os.path.join(AOSPDIR, suffix))
            for suffix in args_list]
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hidl_vec.hpp"),
                                     clang_args=args_list)
        cursor = pr.find_hal_cursor("TestClass")
        assert cursor.kind == CursorKind.CLASS_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 6, 3, 2)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 1
        for struct in pr.type_info['structs']:
            assert len(pr.type_info['structs'][struct]['fields']) >= 1
            assert len(pr.type_info['structs'][struct]['fields']) <= 3
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_hidl_vec.hpp"),
                                     clang_args=args_list)
        pr.create_protobuf("TestClass")
        protoc_args = [PROTOC, "--python_out=.", "TestClass.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./TestClass.proto")
        os.remove("TestClass_pb2.py")

    def test_parse_cpp_class_pointer(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_pointer.hpp"))
        cursor = pr.find_hal_cursor("MyHAL")
        pr.hal_name = "MyHAL"
        assert cursor.kind == CursorKind.CLASS_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 3, 10, 3)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 2
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_pointer.hpp"))
        pr.create_protobuf("MyHAL")
        protoc_args = [PROTOC, "--python_out=.", "MyHAL.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyHAL.proto")
        os.remove("MyHAL_pb2.py")

    def test_parse_cpp_class_union(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_union.hpp"))
        cursor = pr.find_hal_cursor("MyHAL")
        pr.hal_name = "MyHAL"
        assert cursor.kind == CursorKind.CLASS_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        self._check_sizes(pr, 0, 5, 2, 2)
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 1
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_class_union.hpp"))
        pr.create_protobuf("MyHAL")
        protoc_args = [PROTOC, "--python_out=.", "MyHAL.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyHAL.proto")
        os.remove("MyHAL_pb2.py")

    """
    def test_parse_cpp_stdlib_parameter(self):
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_stdlib_parameter.hpp"))
        cursor = pr.find_hal_cursor("MyClass")
        assert cursor.kind == CursorKind.CLASS_DECL
        pr.process_struct(cursor)
        pr.do_stuff(cursor)
        pr.remove_callbacks()
        assert len(pr.type_info['fptr']) == 4
        for fptr in pr.type_info['fptr']:
            assert len(pr.type_info['fptr'][fptr]) == 1
        assert len(pr.type_info['enums']) == 0
        assert len(pr.type_info['structs']) >= 2
        assert len(pr.type_info['reftypes']) >= 2
        # create_protobuf needs uninitialized internal state
        pr = ProtofyCPP(os.path.join(DATADIR, "cpp_stdlib_parameter.hpp"))
        pr.create_protobuf("MyClass")
        protoc_args = [PROTOC, "--python_out=.", "MyClass.proto"]
        protoc = subprocess.Popen(protoc_args, stdout=subprocess.PIPE)
        output = protoc.communicate()[0]
        assert output == b""
        # cleanup
        os.remove("./MyClass.proto")
        os.remove("MyClass_pb2.py")
    """

if __name__ == "__main__":
    unittest.main()
