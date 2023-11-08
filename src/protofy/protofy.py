import sys
import os
from clang.cindex import (
    TypeKind,
    Cursor,
    Type,
)
import logging

from ..common.animator import Animator
from ..common.parser_helper import (
    parse,
    get_definition,
    collect_fptrs,
    collect_fptr_args,
    PRIMITIVE_TYPES,
)

################################################################################
# TYPING
################################################################################

from typing import Tuple, List

################################################################################
# MONKEY PATCHING
################################################################################


def cursor_hash(self):
    return self.hash


def type_hash(self):
    return hash(
        self.spelling,
    )


Cursor.__hash__ = cursor_hash
Type.__hash__ = type_hash

################################################################################
# LOGGING
################################################################################

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

################################################################################
# GLOBALS
################################################################################

C2PB_TYPES = {
    TypeKind.UCHAR: "bytes",
    "char": "bytes",
    "uint8_t": "bytes",
    "const char": "bytes",
    "const uint8_t": "bytes",
    "int": "int32",
    "signed int": "sint32",
    TypeKind.UINT: "uint32",
    "uint32_t": "int32",
    "short int": "int16",
    "signed short int": "int16",
    "unsigned short int": "uint16",
    "uint16_t": "uint16",
    "long int": "int64",
    "signed long int": "int64",
    "unsigned long int": "uint64",
    TypeKind.ULONG: "uint64",
    "uint64_t": "uint64",
    "size_t": "uint64",
    "const size_t": "uint64",
    TypeKind.BOOL: "bool",
    "_Bool": "bool",
}

################################################################################
# CODE
################################################################################


def handle_constantarray(field_type, definitions, type_info=None):
    if field_type.get_array_element_type().get_size() == 1:
        return handle_param(
            field_type.get_array_element_type(), definitions, type_info
        )
    else:
        raise NotImplementedError("Implement me!")


myobj = None


class Protofy:
    def __init__(
        self,
        defintion_identifier: str,
        tu_path: str,
        *clang_args: Tuple[List[str]],
    ):
        global type_info

        self._functions = dict()
        self._types = set()
        self._proto_entries = []
        self._tu = parse(tu_path, *clang_args)

        if not self._tu:
            log.error(f"Error parsing {tu_path}")
            sys.exit(0)

        # look for the definition of `defintion_identifier`
        self._definition = get_definition(self._tu.cursor, defintion_identifier)

        if not self._definition:
            log.error(f"Could not find definition for `{defintion_identifier}`")
            sys.exit(0)

        self._types.add(self._definition.type)
        self._animator = Animator()

        log.debug(
            "{} ({}) of type {} ({})".format(
                self._definition.spelling,
                self._definition.kind,
                self._definition.type.spelling,
                self._definition.type.kind,
            )
        )

        # collect the function pointers withing the `Cursor` pointed to be
        # `self._definition`
        for f in collect_fptrs(self._definition):
            self._types.add(f.type)
            self._functions[f] = []
            self._animator.addEdge(self._definition, f)

        # collect the argument `Cursor`s of each function `Cursor`
        for f in self._functions.keys():
            fargs = collect_fptr_args(f)
            self._functions[f].extend(fargs)
            for arg in self._functions[f]:
                self._animator.addEdge(f, arg)

        for _, args in self._functions.items():
            for arg in args:
                self._animator.addEdge(arg, arg.type)
                # self._types.add(arg.type)
                self._traverse_type(arg.type)

        for t in self._types:
            self.ast2proto(t)

        import ipdb

        ipdb.set_trace()
        self.render()

    def _traverse_type(self, type: Type):

        log.info(f"Type is `{type.spelling}`")

        if type.kind == TypeKind.VOID:
            # cannot do much with a void type
            return

        if type.is_const_qualified():
            decl = type.get_declaration()
            _type = type
            type = decl.type
            assert type.spelling in _type.spelling, "de-constification failed"
            assert (
                "const" not in type.spelling
            ), "de-constification failed, still const"

        if type in self._types:
            log.info(f"Type `{type.spelling}` already known!")
            return
        else:
            self._types.add(type)

        if type.kind == TypeKind.POINTER:
            return self._traverse_pointer_type(type)
        elif type.kind == TypeKind.ELABORATED:
            return self._traverse_type(type.get_canonical())
        elif type.kind == TypeKind.TYPEDEF:
            return self._traverse_typedef(type)
        elif type.kind == TypeKind.ENUM:
            return
        elif type.kind in PRIMITIVE_TYPES:
            return
        elif type.kind == TypeKind.RECORD:
            return self._traverse_record(type)
        # elif (
        #     type.kind == TypeKind.FUNCTIONPROTO
        #     or type.kind == TypeKind.UNEXPOSED
        # ):
        #     # this is the case for fp:
        #     # int (*set_notify)(struct fingerprint_device *dev, fingerprint_notify_t notify);
        #     return type.kind, type.spelling
        # elif type.kind == TypeKind.CONSTANTARRAY:
        #     return handle_constantarray(type, definitions, type_info)
        else:
            log.debug(f"Type {type.spelling}, with kind {type.kind}")
            raise NotImplementedError("Implement me!")

    def _traverse_pointer_type(self, type: Type):

        # handle pointer types
        pointee = type.get_pointee()

        self._traverse_type(pointee)
        return

    def _traverse_typedef(self, type: Type):
        typedef_type = type.get_declaration().underlying_typedef_type
        self._traverse_type(typedef_type)
        return

    def _traverse_record(self, type: Type):
        fields = type.get_fields()
        for field in fields:
            self._traverse_type(field.type)
        return

    def ast2proto(self, type: Type):

        if type.kind == TypeKind.FUNCTIONPROTO:
            # `FUNCTIONPROTO` not relevant for mutators
            return
        elif type.kind == TypeKind.POINTER:
            return
        elif type.kind == TypeKind.ELABORATED:
            return self.ast2proto(type.get_canonical())
        elif type.kind == TypeKind.TYPEDEF:
            idx = 1
            attr = "required"
            pb_type = type.get_declaration().underlying_typedef_type

            out = f"message {type.spelling} {{\n"
            out += f"  {attr} {pb_type.spelling} {type.spelling} = {idx};\n"
            out += "}\n"
            self._proto_entries.append(out)
            return
        elif type.kind == TypeKind.ENUM:
            out = f"enum {type.spelling} {{\n"
            for enum_entry in type.get_declaration().get_children():
                out += (
                    f"  {enum_entry.spelling} = "
                    + f"{enum_entry.enum_value:#x};\n"
                )
            out += "}\n\n"
            self._proto_entries.append(out)
            return
        elif type.kind in PRIMITIVE_TYPES:
            attr = "required"
            pb_type = C2PB_TYPES[type.kind]
            idx = 1
            out = f"  {attr} {pb_type} {type.spelling} = {idx};"
            return
        elif type.kind == TypeKind.RECORD:
            return
            # TODO
            out = f"message {type.spelling} {{\n"
            for idx, field in enumerate(type.get_fields()):
                if field.type.kind == TypeKind.POINTER:
                    attr = "repeated"
                else:
                    attr = "required"
                out += f"  {attr} {pb_type} {type.spelling} = {idx};"
            out += "}\n"
            return
        # elif (
        #     type.kind == TypeKind.FUNCTIONPROTO
        #     or type.kind == TypeKind.UNEXPOSED
        # ):
        #     # this is the case for fp:
        #     # int (*set_notify)(struct fingerprint_device *dev, fingerprint_notify_t notify);
        #     return type.kind, type.spelling
        # elif type.kind == TypeKind.CONSTANTARRAY:
        #     return handle_constantarray(type, definitions, type_info)
        else:
            log.debug(f"Type {type.spelling}, with kind {type.kind}")
            raise NotImplementedError("Implement me!")
        return
        out = ""

        # handle structs
        for struct in type_info["structs"].keys():
            if (
                type_info["structs"][struct]["type"]
                .get_declaration()
                .is_anonymous()
                or "anonymous union" in struct
            ):
                # that's a  union and handled below
                continue
            out += "message {} {{\n".format(struct.split(" ")[-1])
            i = 0
            for field in type_info["structs"][struct]["fields"]:

                #            type_kind, type_spelling, attr = resolve_type(field['type'], [definition])
                type_kind, type_spelling = field["type_spelling"]
                attr = resolve_type(field["type"])

                if (
                    not field["spelling"]
                    and field["type"].get_declaration().is_anonymous()
                ) or "union" in type_spelling:
                    union_name = "{}_union".format(struct.split(" ")[-1])
                    out += "  {} {} {{\n".format("oneof", union_name)
                    # TODO: nested unions?
                    for umember in type_info["structs"][type_spelling]["fields"]:
                        utype_kind, utype_spelling = umember["type_spelling"]

                        if utype_kind in PRIMITIVE_TYPES:
                            utype_spelling = C2PB_TYPES[utype_spelling]
                        out += "    {} {} = {};\n".format(
                            utype_spelling, umember["spelling"], i + 1
                        )
                        i += 1
                    out += "  }\n"
                else:
                    # map c types to protobuf types
                    if type_kind in PRIMITIVE_TYPES:
                        type_spelling = C2PB_TYPES[type_spelling]
                    out += "  {} {} {} = {};\n".format(
                        attr, type_spelling, field["spelling"], i + 1
                    )
                    i += 1

            out += "}\n\n"

        device_name = target_struct.replace("_", " ").split(" ")[1]
        with open("{}.proto".format(device_name), "w") as f:
            f.write('syntax = "proto2";\n\npackage {};\n\n'.format(device_name))
            f.write(out)

    def render(self):
        path = os.path.join("/root/workdir", "animator")
        self._animator.render(path)


# def resolve_type(field_type, definitions):
def resolve_type(field_type):
    if field_type.kind == TypeKind.POINTER:
        attr = "required"
        """
        if field_type.get_pointee().kind == TypeKind.TYPEDEF:
            type_kind, type_spelling, _ = resolve_type(field_type.get_pointee(), definitions)
        else:
            type_kind, type_spelling = handle_param(field_type, definitions)
        """
    elif field_type.kind == TypeKind.TYPEDEF:
        attr = "required"
        """
        try:
        #    t = handle_param(field_type, definitions)
        #    type_kind = t[0]
        #    type_spelling = t[1]
            type_kind, type_spelling = handle_param(field_type, definitions)
        except:
            import ipdb; ipdb.set_trace()
        """
    elif field_type.kind == TypeKind.CONSTANTARRAY:
        attr = "repeated"
        """
        try:
            type_kind, type_spelling = handle_param(field_type.get_array_element_type(), definitions)
        except:
            import ipdb; ipdb.set_trace()
        """
    else:
        attr = "required"
        """
        type_spelling = field_type.spelling
        type_kind = field_type.kind
        """

    return attr  # type_kind, type_spelling, attr
