from clang.cindex import Index, CursorKind, TypeKind, Diagnostic, Type
from .typedmemorydumper import TypedMemoryDumper

import logging


log = logging.getLogger(__name__)


CB_FUNCTIONS = []


class FunctionDumper(object):
    def __init__(self, cursor):
        self.parameters = []
        self.cursor = cursor

        if cursor.kind == CursorKind.CXX_METHOD:
            # the CXX case where the cursor points to CXX_METHOD
            self.parameters.append(("this", None))
            self.result_type = cursor.result_type
        elif cursor.kind == CursorKind.FIELD_DECL:
            # the C case where the cursor points to a field declaration in a struct
            self.result_type = cursor.type.get_pointee().get_result()
        elif cursor.kind == CursorKind.TYPE_ALIAS_DECL:
            # the CXX callback function case
            self.result_type = (
                cursor.underlying_typedef_type.get_canonical()
                .get_template_argument_type(0)
                .get_result()
            )
            # this is also a CXX method
            self.parameters.append(("this", None))
        else:
            log.error("What is this?")
            import ipdb

            ipdb.set_trace()

        for idx, param_cursor in enumerate(cursor.get_children()):
            # it seems that clang does not provide the return value for get_children() for primitive types
            if param_cursor.kind == CursorKind.PARM_DECL:
                log.debug(
                    f"{param_cursor.spelling} ({param_cursor.type.spelling})"
                )

                if param_cursor.spelling == "dev":
                    # we ignore the this reference
                    self.parameters.append(("this", None))
                    continue

                self.parameters.append(
                    (
                        param_cursor.spelling,
                        TypedMemoryDumper(
                            None, self.cursor, param_cursor, param_cursor.type
                        ),
                    )
                )
            elif param_cursor.kind in [
                CursorKind.TYPE_REF,
                CursorKind.TEMPLATE_REF,
                CursorKind.CXX_OVERRIDE_ATTR,
                CursorKind.NAMESPACE_REF,
                CursorKind.COMPOUND_STMT,
            ]:
                # return value case, continue and handle return types consistently below
                continue
            else:
                log.error("What is this?")
                import ipdb

                ipdb.set_trace()

        self.parameters.append(
            (
                "ret",
                TypedMemoryDumper(
                    None, self.cursor, self.cursor, self.result_type
                ),
            )
        )

    def __str__(self):
        params = []
        for idx, param in enumerate(self.parameters):
            # we skip the param if it's the (implicit) `this` pointer
            if idx == 0 and param[0] == "this":
                continue
            if param[0] == "ret":
                ret = f"{param[1]}"
            else:
                params.append(f"{param[1]}")

        out = f"{ret} {self.cursor.spelling}("
        for idx, param in enumerate(params):
            if idx == len(params) - 1:
                # last idx
                out += param + ")"
                break
            out += param + ", "
        return out

    def emit_frida_code(self):

        jscode = []
        log.info("processing {}".format(self))
        for param in self.parameters:
            if param[0] == "this":
                continue
            jscode.append(
                "function dump_{}_{}(arg, args, is_onenter, dump_id){{".format(
                    self.cursor.spelling, param[0]
                )
            )
            jscode.append("  // processing {}".format(param[1].type.spelling))
            jscode.append("  var v0 = arg;")
            jscode.append("  {}".format(param[1].emit_frida_code()))
            jscode.append("}\n")

        return "\n".join(jscode)

    def dispatcher(self):

        jscode = []

        fname = self.cursor.spelling

        jscode.append("""    case "{}":\n""".format(fname))
        jscode.append(
            """
              if (ret == null){ var is_onenter = 1; } else { var is_onenter = 0; };\n"""
        )

        # TODO: we should only do this when the return code is actually indicating an error
        jscode.append("""      if(is_onenter == 0){\n""")
        jscode.append(
            """          dump_{}_ret(ret, args, is_onenter, dump_id);\n""".format(
                fname
            )
        )
        jscode.append("""          if(ret.toInt32() < 0){ break; }\n""")
        jscode.append("""      }\n""")

        # TODO: errors CPP HAL callbacks are indicated by the first param
        # and not the return value
        if fname.endswith("_cb"):
            # this is a CPP HAL callback and needs special treatment
            jscode.append("""      if(is_onenter){\n""")
            jscode.append(
                """          var err = arrayToInt(Memory.readByteArray(args[1], 4));\n"""
            )
            jscode.append("""          if(err != 0){ break; }\n""")
            jscode.append("""      }\n""")

        for param_idx, param_tuple in enumerate(self.parameters):
            argname = param_tuple[0]
            if argname == "ret":
                continue

            if argname == "this":
                # we do not dump `this` (first arg of C++ methods)
                jscode.append(
                    """      if(is_onenter) {{ saved_args.push(args[{}]); }}\n""".format(
                        param_idx
                    )
                )
                continue

            if argname == "dev":
                # first arg for c HAL function pointers
                jscode.append(
                    """      if(is_onenter) {{ saved_args.push(args[{}]); }}\n""".format(
                        param_idx
                    )
                )
                continue

            jscode.append(
                """      if(is_onenter) {{ saved_args.push(args[{}]); }}\n""".format(
                    param_idx
                )
            )

            if (
                param_tuple[1].cursor.type.kind == TypeKind.POINTER
                and not param_tuple[1]
                .cursor.type.get_pointee()
                .is_const_qualified()
            ):
                # param is ptr but not const qualified, therefore we treat it as an output param and only dump it onLeave
                jscode.append("""      if(is_onenter == 0){\n""")
                jscode.append(
                    """         dump_{}_{}(args[{}], args, is_onenter, dump_id);\n""".format(
                        fname, argname, param_idx
                    )
                )
                jscode.append("""      }\n""")
            else:
                # param is ptr and const qualified or scalar, therefore we treat it as an input param and dump it onEnter *and* onLeave
                jscode.append(
                    """      dump_{}_{}(args[{}], args, is_onenter, dump_id);\n""".format(
                        fname, argname, param_idx
                    )
                )

        jscode.append("      break;\n")
        return "\n".join(jscode)
