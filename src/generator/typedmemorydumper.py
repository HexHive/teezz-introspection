from clang.cindex import Index, CursorKind, TypeKind, Diagnostic, Type, Cursor
import logging
from . import functiondumper


log = logging.getLogger(__name__)


LENGTH_KEYWORDS = ["length", "len", "size", "sz"]
PTRSZ = 8


PRIMITIVE_TYPES = [
    TypeKind.BOOL,
    TypeKind.UCHAR,
    TypeKind.CHAR_S,
    TypeKind.SCHAR,
    TypeKind.SHORT,
    TypeKind.USHORT,
    TypeKind.INT,
    TypeKind.UINT,
    TypeKind.LONG,
    TypeKind.ULONG,
]


class TypedMemoryDumper:
    def __init__(self, parent_dumper, parent_cursor, cursor, type_, varno=0):

        # assert (parent.type.get_pointee().kind == TypeKind.FUNCTIONPROTO) or (
        #     parent.kind == CursorKind.CXX_METHOD
        # ), "Wrong type for `parent`"

        # `parent` should be a cursor to the language construct containing `cursor`
        # (1) `cursor`'s `STRUCT_DECL` if `cursor` is a `FIELD_DECL`
        # (2) `cursor`'s `FUNCTIONPROTO` if `cursor` is a `PARAM_DECL`

        if not isinstance(parent_cursor, Cursor):
            import ipdb

            ipdb.set_trace()

        if parent_cursor.kind == CursorKind.FIELD_DECL:
            if (
                not parent_cursor.type.get_pointee().kind
                == TypeKind.FUNCTIONPROTO
            ):
                import ipdb

                ipdb.set_trace()
        elif parent_cursor.kind == CursorKind.STRUCT_DECL:
            pass
        elif parent_cursor.kind == CursorKind.UNION_DECL:
            pass
        elif parent_cursor.kind == CursorKind.PARM_DECL:
            pass
        elif parent_cursor.kind == CursorKind.CLASS_DECL:
            pass
        elif parent_cursor.kind == CursorKind.CXX_METHOD:
            pass
        elif parent_cursor.kind == CursorKind.TYPE_ALIAS_DECL:
            parent_cursor.underlying_typedef_type.get_canonical().get_template_argument_type(
                0
            ).kind == TypeKind.FUNCTIONPROTO
        else:
            import ipdb

            ipdb.set_trace()

        self.parent_dumper = parent_dumper
        self.parent = parent_cursor
        self.cursor = cursor
        self.type = type_
        self.varno = varno

    def __str__(self):
        return self.type.spelling

    def _get_orig_decl(self):
        """Retrieve a `Cursor` object pointing to the declaration
        (`CursorKind.PARM_DECL` or `CursorKind.FIELD_DECL`) this `self` instance
        originates from."""

        if self.cursor.kind == CursorKind.PARM_DECL:
            return self.cursor

        curr_parent_dumper = self.parent_dumper
        while curr_parent_dumper is not None:
            if curr_parent_dumper.cursor.kind == CursorKind.PARM_DECL:
                return curr_parent_dumper.cursor
            curr_parent_dumper = curr_parent_dumper.parent_dumper
        # if we reached the top of the hierarchy and have not found a `PARM_DECL` yet,
        # this must be the return value case.

        # sanity checks
        if (
            self.cursor.type.kind is TypeKind.POINTER
            and self.cursor.type.get_pointee().kind is TypeKind.FUNCTIONPROTO
        ):
            # the C case where the cursor is a function proto
            pass
        elif (
            self.cursor.kind is CursorKind.CXX_METHOD
            and self.cursor.type.kind is TypeKind.FUNCTIONPROTO
        ):
            # the CPP case where the crusor is a CXX method
            pass
        else:
            pass
            # import ipdb

            # ipdb.set_trace()

        return self.cursor

    def emit_frida_code(self):
        jscode = []
        jscode.append("{}".format(self.handle_type(self.type, self.varno)))
        return "\n".join(jscode)

    def gen_send(self, type, varno):
        """generate the js code to send our dump to the host."""
        out = ""
        out += "send({ 'type' : 'dump', "
        out += "'on_enter': is_onenter, "
        orig_decl = self._get_orig_decl()
        out += "'param': '{}', ".format(orig_decl.spelling)
        out += "'param_type' : '{}', ".format(type.spelling)
        out += "'dump_id': dump_id  }}, v{});".format(varno)
        return out

    def handle_type(self, type, varno):
        jscode = []
        jscode.append(f"// param type is '{type.spelling}' ({type.kind})")

        if type.kind in PRIMITIVE_TYPES:
            jscode.append(self.handle_primitive(type, varno))
        elif type.kind == TypeKind.ENUM:
            jscode.append(self.handle_enum(type, varno))
        elif type.kind == TypeKind.LVALUEREFERENCE:
            jscode.append(self.handle_lvaluereference(type, varno))
        elif type.kind == TypeKind.UNEXPOSED:
            jscode.append(self.handle_unexposed(type, varno))
        elif type.kind == TypeKind.TYPEDEF:
            jscode.append(self.handle_typedef(type, varno))
        elif type.kind == TypeKind.ELABORATED:
            jscode.append(self.handle_elaborated(type, varno))
        elif type.kind == TypeKind.RECORD:
            jscode.append(self.handle_record(type, varno))
        elif type.kind == TypeKind.CONSTANTARRAY:
            jscode.append(self.handle_constantarray(type, varno))
        elif type.kind == TypeKind.POINTER:
            jscode.append(self.handle_pointer(type, varno))
        elif type.kind == TypeKind.INVALID:
            pass
        elif type.kind == TypeKind.VOID:
            pass
        elif type.kind == TypeKind.FUNCTIONPROTO:
            # These are function pointers, which we ignore
            pass
        else:
            import ipdb

            ipdb.set_trace()
            raise NotImplementedError(
                "Implement me! TypeKind: {}".format(type.kind)
            )

        return "\n".join(jscode)

    def handle_primitive(self, type, varno):
        jscode = []
        jscode.append("// primitive type: {}".format(type.spelling))
        jscode.append("if( !(v{} instanceof ArrayBuffer) ) {{".format(varno))
        jscode.append(
            "v{} = intToArray(v{}, {});".format(varno, varno, type.get_size())
        )
        jscode.append("}")
        jscode.append(self.gen_send(type, varno))
        return "\n".join(jscode)

    def handle_enum(self, type, varno):
        jscode = []
        jscode.append("// enum {}".format(type.spelling))
        jscode.append("if( !(v{} instanceof ArrayBuffer) ) {{".format(varno))
        jscode.append(
            "v{} = intToArray(v{}, {});".format(varno, varno, type.get_size())
        )
        jscode.append("}")
        jscode.append(self.gen_send(type, varno))
        return "\n".join(jscode)

    def handle_lvaluereference(self, type, varno):
        jscode = []

        pointee = type.get_pointee()

        if pointee.get_declaration().spelling == "Vector":
            # libclang's python bindings do not support retrieving the size of
            # vectors. We do it manually as a workaround.
            # FIXME: in the long run, this should not be done manually
            jscode.append(
                f"var v{varno+1} = Memory.readByteArray(v{varno}, {4*PTRSZ});"
            )
        elif pointee.get_declaration().spelling == "hidl_vec":
            jscode.append(
                f"var v{varno+1} = Memory.readByteArray(v{varno}, {4*PTRSZ});"
            )
        elif pointee.get_declaration().spelling == "hidl_string":
            jscode.append(
                f"var v{varno+1} = Memory.readByteArray(v{varno}, {4*PTRSZ});"
            )
        elif pointee.get_declaration().spelling in ["KeyedVector", "List"]:
            # we do not support `KeyedVector`
            return ""
        else:
            assert pointee.get_size() > 0, "Pointee size smaller zero"
            jscode.append(
                f"var v{varno+1} = Memory.readByteArray(v{varno}, {pointee.get_size()});"
            )

        if pointee.get_canonical().kind in [TypeKind.RECORD]:
            lvalue_dumper = TypedMemoryDumper(
                self,
                pointee.get_declaration(),
                pointee.get_declaration(),
                pointee,
                varno + 1,
            )
            jscode.append(lvalue_dumper.emit_frida_code())
        else:
            jscode.append(self.handle_type(pointee, varno + 1))
        return "\n".join(jscode)

    def handle_elaborated(self, type, varno):
        cursor = type.get_declaration()
        if cursor.kind == CursorKind.STRUCT_DECL:
            self.parent = cursor
        jscode = self.handle_type(type.get_canonical(), varno)
        return jscode

    def handle_unexposed(self, type, varno):
        return self.handle_type(type.get_canonical(), varno)

    def handle_typedef(self, type, varno):
        typedef_type = type.get_declaration().underlying_typedef_type
        return self.handle_type(typedef_type, varno)

    def handle_constantarray(self, type, varno):
        jscode = []
        sz = type.get_array_element_type().get_size()
        n = type.get_array_size()

        jscode.append("// It's a CONSTANTARRAY!")
        jscode.append(self.gen_send(type, varno))
        return "\n".join(jscode)

    class Record:
        def __init__(self, type_):
            self.type = type_

        def __str__(self):
            out = ""
            fields = list(self.type.get_fields())

            out += "Record {} {{\n".format(self.type.spelling)
            # import ipdb; ipdb.set_trace()
            for idx, field in enumerate(fields):
                if idx < len(fields) - 1:
                    out += "\t{} {},\n".format(
                        field.type.spelling, field.spelling
                    )
                else:
                    out += "\t{} {}\n".format(
                        field.type.spelling, field.spelling
                    )
            out += "}"
            return out

    @staticmethod
    def search_pointer(type):
        pointer = None
        if type.kind == TypeKind.ELABORATED:
            pointer = TypedMemoryDumper.search_pointer(type.get_canonical())
        elif type.kind == TypeKind.RECORD:
            for field in type.get_fields():
                pointer = TypedMemoryDumper.search_pointer(field.type)
                if pointer:
                    break
        elif type.kind == TypeKind.POINTER:
            pointer = type
        elif type.kind == TypeKind.ENUM:
            return None
        elif type.kind == TypeKind.BOOL:
            return None
        elif type.kind == TypeKind.CHAR_S:
            return None
        elif type.kind == TypeKind.UINT:
            return None
        elif type.kind == TypeKind.INT:
            return None
        elif type.kind == TypeKind.ULONG:
            return None
        elif type.kind == TypeKind.LONG:
            return None
        elif type.kind == TypeKind.TYPEDEF:
            typedef_type = type.get_declaration().underlying_typedef_type
            return TypedMemoryDumper.search_pointer(typedef_type)
        else:
            raise NotImplementedError(
                "Implement me! TypeKind: {}".format(type.kind)
            )
        return pointer

    def handle_record_template(self, type, varno):
        jscode = []

        # we only support vector and hidl_vec for now
        if type.get_declaration().spelling == "vector":
            # figure out size

            # slice start pointer as int from the record
            jscode.append(
                f"var v{varno+1} = arrayToInt(v{varno}.slice(0, {PTRSZ}));"
            )
            # jscode.append(f"console.log('start: ' + v{varno+1});")

            # slice end pointer as int from the record
            jscode.append(
                f"var v{varno+2} = arrayToInt(v{varno}.slice({PTRSZ}, {2*PTRSZ}));"
            )
            # jscode.append(f"console.log('end: ' + v{varno+2});")

            # calc current sz
            jscode.append(f"var v{varno+3} = v{varno+2} - v{varno+1};")
            # jscode.append(f"console.log('sz: ' + v{varno+3});")

            tmpl_type = type.get_template_argument_type(0)
            elem_sz = tmpl_type.get_size()

            # if type.get_template_argument_type(0) is a primitive type,
            # we can simply read all elements and be done

            if tmpl_type.kind in PRIMITIVE_TYPES or tmpl_type.get_size() in [
                1,
                2,
                4,
            ]:
                jscode.append(f"var v{varno+4} = ptr(v{varno+1});")
                jscode.append(
                    f"var v{varno+5} = Memory.readByteArray(v{varno+4}, {elem_sz} * v{varno+3});"
                )
                jscode.append(self.gen_send(type, varno + 5))
            else:
                jscode.append(
                    f"for (var i = 0; i*{elem_sz} < v{varno+3}; i++) {{"
                )

                jscode.append(
                    f"var v{varno+4} = ptr(v{varno+1}).add(i*{elem_sz});"
                )

                jscode.append(
                    f"var v{varno+5} = Memory.readByteArray(v{varno+4}, {elem_sz});"
                )

                # code = f"console.log(hexdump(v{varno+5}, {{ ansi: true }}));"
                # jscode.append(code)

                jscode.append(
                    self.handle_type(
                        type.get_template_argument_type(0), varno + 5
                    )
                )

                jscode.append("}")
                # traverse sz times into type.get_template_argument_type(0)

        elif type.get_declaration().spelling == "hidl_vec":
            # figure out size

            # slice mBuffer pointer as int from the record
            jscode.append(
                f"var v{varno+1} = arrayToInt(v{varno}.slice(0, {PTRSZ}));"
            )
            jscode.append(f"console.log('mBuffer: ' + v{varno+1});")

            # slice mSize pointer as int from the record
            jscode.append(
                f"var v{varno+3} = arrayToInt(v{varno}.slice({PTRSZ}, {PTRSZ+4}));"
            )
            jscode.append(f"console.log('mSize: ' + v{varno+3});")

            tmpl_type = type.get_template_argument_type(0)
            elem_sz = tmpl_type.get_size()

            # if type.get_template_argument_type(0) is a primitive type,
            # we can simply read all elements and be done

            if tmpl_type.kind in PRIMITIVE_TYPES or tmpl_type.get_size() in [
                1,
                2,
                4,
            ]:
                jscode.append(f"var v{varno+4} = ptr(v{varno+1});")
                jscode.append(
                    f"var v{varno+5} = Memory.readByteArray(v{varno+4}, {elem_sz} * v{varno+3});"
                )
                jscode.append(self.gen_send(type, varno + 5))
            else:
                jscode.append(
                    f"for (var i = 0; i*{elem_sz} < v{varno+3}; i++) {{"
                )

                jscode.append(
                    f"var v{varno+4} = ptr(v{varno+1}).add(i*{elem_sz});"
                )

                jscode.append(
                    f"var v{varno+5} = Memory.readByteArray(v{varno+4}, {elem_sz});"
                )

                # code = f"console.log(hexdump(v{varno+5}, {{ ansi: true }}));"
                # jscode.append(code)

                jscode.append(
                    self.handle_type(
                        type.get_template_argument_type(0), varno + 5
                    )
                )

                jscode.append("}")
        elif type.get_declaration().spelling == "hidl_pointer":
            pass
        elif type.get_declaration().spelling == "Vector":
            # We do not support `Vector`
            return ""
        else:
            import ipdb

            ipdb.set_trace()
        return "\n".join(jscode)

    def handle_record(self, type, varno):
        """Descends into a record."""
        jscode = []
        jscode.append("/*")
        jscode.append("{}".format(TypedMemoryDumper.Record(type)))
        jscode.append("*/")

        self.varno = varno
        self.type = type

        if (
            type.get_num_template_arguments() > 0
            and (
                type.get_size() < 0
                or (type.get_size() > 0 and len(list(type.get_fields())) == 0)
            )
            and type.get_declaration().spelling not in ["function", "Return"]
        ):
            jscode.append(self.handle_record_template(type, varno))
            return "\n".join(jscode)

        for idx, field in enumerate(type.get_fields()):
            field_size = field.type.get_size()
            assert field.get_field_offsetof() % 8 == 0
            offset = field.get_field_offsetof() // 8

            jscode.append(
                "// {} {}".format(field.spelling, field.type.spelling)
            )
            jscode.append(
                "var v{} = v{}.slice({}, {});".format(
                    varno + 1 + idx, varno, offset, offset + field_size
                )
            )

            # if "keymaster_key_param_t" in field.type.spelling:
            #     import ipdb

            #     ipdb.set_trace()

            # if (
            #     field.type.kind == TypeKind.ELABORATED
            #     and field.type.get_declaration().kind == CursorKind.UNION_DECL
            # ):
            if field.type.get_declaration().kind == CursorKind.UNION_DECL:
                # this field is a union
                jscode.append("// This is a union.")

                # does this union contain pointer members?
                pointer = TypedMemoryDumper.search_pointer(field.type)

                if pointer:
                    # the union contains pointer members but we do not know
                    # if it is actually used as a pointer.
                    # our heuristic is to see if it points to rw memory.

                    # slice the pointer from the record
                    jscode.append(
                        "var v{} = v{}.slice({}, {});".format(
                            varno + 1 + idx, varno, offset, offset + field_size
                        )
                    )

                    # convert to native pointer
                    jscode.append(
                        "var v{} = new NativePointer(arrayToInt(v{}));".format(
                            varno + 2 + idx, varno + 1 + idx
                        )
                    )
                    # does it point to a mapped location?
                    jscode.append(
                        "var range_obj = Process.findRangeByAddress(v{});".format(
                            varno + 2 + idx
                        )
                    )

                    # if it points to something, treat the member as a pointer
                    jscode.append("if (range_obj) {")

                    jscode.append("try {")
                    field_dumper = TypedMemoryDumper(
                        self,
                        type.get_declaration(),
                        self.cursor,
                        pointer,
                        varno + 2 + idx,
                    )
                    jscode.append(field_dumper.emit_frida_code())
                    jscode.append(
                        f"}} catch (e) {{ console.log(v{varno + 2 + idx} + ' access resulted in an exception'); }}"
                    )

                    # otherwise, take the union's memory
                    jscode.append("} else {")
                    jscode.append(self.gen_send(field.type, varno + 1 + idx))
                    jscode.append("}")
                else:
                    jscode.append(self.gen_send(field.type, varno + 1 + idx))
            elif field.type.kind == TypeKind.POINTER:
                jscode.append("// This is a pointer.")
                jscode.append(
                    "v{} = new NativePointer(arrayToInt(v{}));".format(
                        varno + 1 + idx, varno + 1 + idx
                    )
                )
                # further traverse into this type
                field_dumper = TypedMemoryDumper(
                    self,
                    type.get_declaration(),
                    field,
                    field.type,
                    varno + 1 + idx,
                )
                jscode.append(field_dumper.emit_frida_code())
            else:
                # further traverse into this type
                field_dumper = TypedMemoryDumper(
                    self,
                    type.get_declaration(),
                    field,
                    field.type,
                    varno + 1 + idx,
                )
                jscode.append(field_dumper.emit_frida_code())

        if len(list(type.get_fields())) == 0:
            if (
                type.get_num_template_arguments() == 1
                and type.get_template_argument_type(0).kind
                == TypeKind.FUNCTIONPROTO
            ):
                """this is the hidl callback case"""

                func = self.parent.spelling
                handle = f"{func}_{self.cursor.spelling}"

                # FIXME: we are using some magic values here
                jscode.append(
                    f"""
                var v1 = Memory.readPointer(v0.add(32));
                var v2 = Memory.readPointer(v1).add(48);
                var v3 = Memory.readPointer(v2);

                if (is_onenter) {{
                  fptr_{handle} = Interceptor.attach(v3, {{
                    onEnter: function(args) {{
                      console.log("onEnter: {handle}()");

                      // for debugging
                      //console.log("{handle} called from:\\n" +
                      //  Thread.backtrace(this.context, Backtracer.ACCURATE)
                      //  .map(DebugSymbol.fromAddress).join("\\n") + "\\n");

                      // we assign a fresh DUMP_ID to callbacks because it has not been increaded by the caller's onLeave yet
                      DUMP_ID += 1;
                      this.dump_id = DUMP_ID;
                      this.args = new Array();
                      send({{
                          'type': 'init_dump',
                          'func': '{handle}',
                          'dump_id': this.dump_id
                      }});
                      dump("{func}_cb", args, this.args, null, this.dump_id);
                    }},
                    onLeave: function(ret) {{
                      console.log("onLeave: {handle} ()");

                      send({{ 'type' : 'fini_dump',
                            'func' : '{handle}',
                            'dump_id': this.dump_id
                      }});
                    }}
                  }});
                }} else {{
                  fptr_{handle}.detach();
                }}
                """
                )

                # In the hidl-based hal, parameters are returned using callback functions (cbs).
                # In CXX, the parameter containing the callback function is usually a typedef
                # assert (
                #     self.cursor.kind == CursorKind.PARM_DECL
                # ), "Cursor should point to PARM_DECL here."
                if self.cursor.kind != CursorKind.PARM_DECL:
                    import ipdb

                    ipdb.set_trace()
                assert (
                    self.cursor.type.kind == TypeKind.TYPEDEF
                ), "Type should be TYPEDEF here."

                if (
                    self.cursor.type.get_declaration().kind
                    == CursorKind.TYPE_ALIAS_DECL
                ):
                    f_dumper = functiondumper.FunctionDumper(
                        self.cursor.type.get_declaration()
                    )
                    functiondumper.CB_FUNCTIONS.append(f_dumper)
                else:
                    log.error("Investigate this case!")
                    import ipdb

                    ipdb.set_trace()
                    raise NotImplementedError("Implement me!")

        return "\n".join(jscode)

    def _contains_size_keyword(self, s):
        any(
            [
                True
                for keyword in LENGTH_KEYWORDS
                if keyword in s.spelling.lower()
            ]
        )

    def handle_pointer(self, type, varno):
        jscode = []
        jscode.append("// {}".format(type.spelling))

        jscode.append("if(v{} != 0){{".format(varno))

        pointee = type.get_pointee()
        if self.parent.type.spelling in pointee.spelling:
            # recursive definition
            return ""

        """
        this code has a param char* or struct foo* in mind and does not handle
        - pointers to structs containing callback functions (as in the case of fp)

        it also searches for a `size` member indicating the number of chars pointed to by char* or
        number of foos pointed to by struct foo*. that's an assumption that needs to be revisited.
        """
        # work your way up to see if we have a size member
        found_size = False
        curr_dumper_parent = self
        record_nesting_lvl = 0

        while True:
            curr_parent = curr_dumper_parent.parent
            if (
                curr_parent.kind == CursorKind.FIELD_DECL
                and curr_parent.type.kind == TypeKind.POINTER
                and curr_parent.type.get_pointee().kind
                == TypeKind.FUNCTIONPROTO
            ):
                # The current cursor points to a parameter of a function
                # pointer. More specifically, the parent is a field declaration
                # and this field is a function pointer we scan the neighboring
                # parameter and look for a `size` member if we find a `size`
                # member, we record `size` elements of whatever `type` is
                # pointing to if not, we check if it is a C-string
                children = [c for c in list(curr_parent.get_children())]
                found = False
                for idx, c in enumerate(children):
                    if c.spelling == self.cursor.spelling:
                        # found the param
                        found = True
                if not found:
                    # something went horribly wrong
                    import ipdb

                    ipdb.set_trace()
                if idx == 0 or (
                    idx == 1 and children[0].kind is not CursorKind.PARM_DECL
                ):
                    # only look at the forward neighbor
                    if len(children) > idx + 1:
                        if self._contains_size_keyword(
                            children[idx + 1].spelling
                        ):
                            parent_varno = 0
                            jscode.append(
                                "var len{} = args[{}];".format(
                                    parent_varno, idx + 1
                                )
                            )
            elif (
                curr_parent.kind == CursorKind.CXX_METHOD
                and curr_parent.type.kind == TypeKind.FUNCTIONPROTO
            ):
                pass
            elif curr_parent.type.kind == TypeKind.RECORD:
                record_nesting_lvl += 1
                for field in curr_parent.type.get_fields():
                    if any(
                        [
                            True
                            for keyword in LENGTH_KEYWORDS
                            if keyword in field.spelling.lower()
                        ]
                    ):
                        offset = field.get_field_offsetof() // 8
                        size = field.type.get_size()
                        found_size = True
                        break
            elif (
                curr_parent.type.kind == TypeKind.POINTER
                and curr_parent.kind == CursorKind.FIELD_DECL
            ):
                # the C case where we reached the field declaration in the struct of the HAL device
                for field in curr_parent.get_children():
                    if any(
                        [
                            True
                            for keyword in LENGTH_KEYWORDS
                            if keyword in field.spelling.lower()
                        ]
                    ):
                        offset = field.get_field_offsetof() // 8
                        size = field.type.get_size()
                        found_size = True
                        curr_parent = None
                        break
            elif curr_parent.kind in [CursorKind.TYPE_ALIAS_DECL]:
                pass
            else:
                import ipdb

                ipdb.set_trace()
                raise NotImplementedError(
                    "Implement me! TypeKind: {}".format(type.kind)
                )

            if not found_size and curr_dumper_parent.parent_dumper != None:
                curr_dumper_parent = curr_dumper_parent.parent_dumper
                continue
            break  # there are not parents left to look for a size, we stop searching

        if found_size:
            # FIXME: we need a stable convention for this
            # the varno is dependend on the level of nesting
            parent_varno = varno - record_nesting_lvl

            jscode.append(
                "var len{} = arrayToInt(v{}.slice({}, {}));".format(
                    parent_varno, parent_varno, offset, offset + size
                )
            )

            if pointee.kind == TypeKind.UNEXPOSED:
                canonical_type = pointee.get_canonical()
            else:
                canonical_type = pointee

            if canonical_type.kind in PRIMITIVE_TYPES or pointee.get_size() in [
                1,
                2,
                4,
            ]:
                jscode.append(
                    "var v{} = Memory.readByteArray(v{}, {} * len{});".format(
                        varno + 1, varno, pointee.get_size(), parent_varno
                    )
                )
                jscode.append(self.gen_send(type, varno + 1))
            else:
                jscode.append(
                    "for (var i{} = 0; i{} < parseInt(len{}); i{}++) {{".format(
                        parent_varno, parent_varno, parent_varno, parent_varno
                    )
                )

                assert pointee.get_size() > 0, "Pointee size smaller zero"
                jscode.append(
                    "var v{} = v{}.add(i{}*{});".format(
                        varno + 1, varno, parent_varno, pointee.get_size()
                    )
                )
                jscode.append(
                    "var v{} = Memory.readByteArray(v{}, {});".format(
                        varno + 2, varno + 1, pointee.get_size()
                    )
                )
                jscode.append(self.handle_type(pointee, varno + 2))
                jscode.append("}")

        elif pointee.kind == TypeKind.VOID:
            jscode.append("// pointee is void pointer")
        elif (
            self.cursor.type.get_pointee().kind == TypeKind.TYPEDEF
            and self.cursor.type.get_pointee()
            .get_declaration()
            .underlying_typedef_type
            == TypeKind.CHAR_S
        ):
            # this is a typedef-ed C-string
            jscode.append(
                "var v{} = Memory.readCString(v{});".format(varno + 1, varno)
            )
            jscode.append(
                "v{} = Memory.readByteArray(v{}, v{}.length+1);".format(
                    varno + 1, varno, varno + 1
                )
            )
            jscode.append(self.gen_send(type, varno + 1))
        elif (
            self.cursor.type.get_pointee().kind == TypeKind.UNEXPOSED
            and self.cursor.type.get_pointee().get_canonical().kind
            == TypeKind.CHAR_S
        ):
            # this is a const C-string
            jscode.append(
                "var v{} = Memory.readCString(v{});".format(varno + 1, varno)
            )
            jscode.append(
                "v{} = Memory.readByteArray(v{}, v{}.length+1);".format(
                    varno + 1, varno, varno + 1
                )
            )
            jscode.append(self.gen_send(type, varno + 1))
        elif type.get_pointee().kind == TypeKind.CHAR_S:
            # this is a C-string
            jscode.append(
                "var v{} = Memory.readCString(v{});".format(varno + 1, varno)
            )
            jscode.append(
                "v{} = Memory.readByteArray(v{}, v{}.length+1);".format(
                    varno + 1, varno, varno + 1
                )
            )
            jscode.append(self.gen_send(type, varno + 1))
        else:
            if (
                pointee.get_size() <= 0
                and pointee.get_declaration().spelling == "Vector"
            ):
                jscode.append(
                    f"var v{varno+1} = Memory.readByteArray(v{varno}, {4*PTRSZ});"
                )
            else:
                assert pointee.get_size() > 0, "Pointee size smaller zero"
                jscode.append(
                    "var v{} = Memory.readByteArray(v{}, {});".format(
                        varno + 1, varno, pointee.get_size()
                    )
                )

            if pointee.kind == TypeKind.POINTER:
                # this is a pointer, we pass it as such
                jscode.append(
                    "var v{} = new NativePointer(arrayToInt(v{}));".format(
                        varno + 1, varno + 1
                    )
                )

            jscode.append(self.handle_type(pointee, varno + 1))

        jscode.append("}")

        return "\n".join(jscode)
