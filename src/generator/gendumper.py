import sys
import logging
import jsbeautifier

import clang.cindex
from clang.cindex import Cursor, CursorKind, TypeKind, Type

# from common.animator import Animator
from common.parser_helper import (
    parse,
    get_definition,
    collect_fptrs,
    collect_fptr_args,
    PRIMITIVE_TYPES,
)

from . import frida_snippets as fs

################################################################################
# TYPING
################################################################################

from typing import Tuple, List, Optional, Set, Dict

################################################################################
# LOGGING
################################################################################

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

################################################################################
# GLOBALS
################################################################################

LENGTH_KEYWORDS = ["length", "len", "size", "sz"]
POINTER_SZ = 8

################################################################################
# CODE
################################################################################


def is_template(node):
    if (
        node.kind == CursorKind.CLASS_TEMPLATE
        or node.kind == CursorKind.CLASS_TEMPLATE_PARTIAL_SPECIALIZATION
    ):
        return True
    return False


def inspect_templates(tu):
    # Traverse the AST and check if a cursor is a template
    for cursor in tu.cursor.walk_preorder():
        # print(f"{cursor.spelling} ({cursor.type.spelling}) - {cursor}")
        if is_template(cursor):
            # print(f"{cursor.spelling} is a template type.")
            # if (
            #     "vector" == cursor.spelling
            #     and cursor.kind == CursorKind.CLASS_TEMPLATE
            # ):
            if "vector" in cursor.spelling:
                print(
                    f"{cursor.spelling} ({cursor.type.spelling}) is a template type."
                )
                # for idx, node, depth in cursor.mywalk_preorder():
                #     print(
                #         "    " * depth
                #         + f"{idx} {node.spelling} ({node.kind}) -- {node.type.spelling} ({node.type.kind})"
                #     )

                # import ipdb

                # ipdb.set_trace()

        # if node.kind == CursorKind.CLASS_DECL:
        #     import ipdb

        #     ipdb.set_trace()


def print_ast(tu):
    for idx, node, depth in tu.cursor.mywalk_preorder():
        print(
            "    " * depth
            + f"{idx} {node.spelling} ({node.kind}) -- {node.type.spelling} ({node.type.kind})"
        )


def print_ast_from_cursor(cursor):
    for idx, node, depth in cursor.mywalk_preorder():
        print(
            "    " * depth
            + f"{idx} {node.spelling} ({node.kind}) -- {node.type.spelling} ({node.type.kind})"
        )


def mywalk_preorder(self, idx=0, depth=0):
    """Depth-first preorder walk over the cursor and its descendants.

    Yields cursors.
    """

    yield idx, self, depth

    child_depth = depth
    for child_idx, child in enumerate(self.get_children()):
        # reset depth to the current depth of children
        depth = child_depth
        for i, descendant, depth in child.mywalk_preorder(child_idx, depth + 1):
            yield i, descendant, depth
            # never executed


Cursor.mywalk_preorder = mywalk_preorder


class IntrospectionException(Exception):
    pass


class IntrospectionRecorderGenerator:
    def __init__(
        self,
        defintion_identifier: str,
        tu_path: str,
        *clang_args: Tuple[List[str]],
    ):

        # functions work queue
        self._functions_wq = list()
        # dictionary for all functions
        self._functions = dict()
        self._finished_types: Set[Type] = set()

        self._current_function = None
        self._current_arg_idx = None
        self._current_arg_name = None
        self._current_record = None
        self._current_record_depth = 0
        self._current_field_idx = None
        self._current_field_name = None
        self._current_parent = None

        self._tu = parse(tu_path, *clang_args)

        if not self._tu:
            log.error(f"Error parsing {tu_path}")
            sys.exit(1)

        # look for the definition of `defintion_identifier`
        self._definition = get_definition(self._tu.cursor, defintion_identifier)

        if not self._definition:
            log.error(f"Could not find definition for `{defintion_identifier}`")
            sys.exit(1)

        # self._animator = Animator()

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
        fptrs = collect_fptrs(self._definition)

        # collect the argument `Cursor`s of each function `Cursor`
        for fptr in fptrs:
            fargs = collect_fptr_args(fptr)
            self._functions_wq.append((fptr, fargs))

        self._param_recorders: Dict[str, List[str]] = dict()
        self._func_dispatchers: List[str] = []

        while self._functions_wq:
            func, args = self._functions_wq.pop()
            self._functions[func] = args

            self._param_recorders[func.spelling] = []
            self._param_recorders[func.spelling].extend(
                self._generate_param_recorders(func, args)
            )
            self._param_recorders[func.spelling].append(
                self._generate_ret_recorder(func)
            )

        for func, args in self._functions.items():
            # why don't we include the generation of dispatchers in the previous
            # loop? Because `self._functions` and `self._param_recorders` might
            # be updated udring the genertion of param/ret recoders. This might
            # be the case when we encounter a parameter which is a callback
            # function.
            self._func_dispatchers.append(self._generate_dispatchers(func, args))

    def _generate_ret_recorder(self, func: Cursor):
        self._current_parent = func
        self._current_arg_idx = None
        self._current_arg_name = "ret"

        # the AST cursor `func` points to the AST node of the function we want
        # to generate the return value recorder for here.
        # In C, this cursor is a `TypeKind.Pointer` to a
        # `TypeKind.FUNCTIONPROTO`.
        # In CPP, this cursor is directly a `TypeKind.FUNCTIONPROTO`.
        if func.type.kind == TypeKind.FUNCTIONPROTO:
            return_type = func.type.get_result()
        elif func.type.kind == TypeKind.POINTER:

            return_type = func.type.get_pointee().get_result()
        elif func.kind == CursorKind.TYPE_ALIAS_DECL:
            template_type = func.underlying_typedef_type.get_canonical().get_declaration().type
            assert (
                template_type.get_num_template_arguments() > 0
                ), "Template arguments missing"
            return_type = template_type.get_template_argument_type(0).get_result()
        else:
            raise IntrospectionException("Wrong `TypeKind` for `func`.")

        jscode = []

        open_arg_ctx_js = fs.call_open_arg_ctx(
            func.spelling, "ret", return_type.spelling
        )
        close_arg_ctx_js = fs.call_close_arg_ctx(
            func.spelling, "ret", return_type.spelling
        )

        jscode.append(open_arg_ctx_js)
        jscode.append("var v0 = arg;")
        ret, traverse_snippet = self._traverse_type(return_type)
        if ret:
            raise IntrospectionException("Return type processing failed.")
        jscode.append(traverse_snippet)

        jscode.append(close_arg_ctx_js)

        recorder_snippet = fs.record_param(func.spelling, "ret", "".join(jscode))
        return recorder_snippet

    def recorders2str(self) -> str:
        out = ""
        out += fs.js_globals()
        out += fs.marshal_scalar()
        out += fs.marshal_param()
        out += fs.deref_pointer()
        out += fs.open_arg_ctx()
        out += fs.close_arg_ctx()
        out += fs.open_record_ctx()
        out += fs.close_record_ctx()
        out += fs.open_array_ctx()
        out += fs.close_array_ctx()
        out += fs.dispatcher("".join(self._func_dispatchers))
        for func_name, arg_recorders in self._param_recorders.items():

            # add separator comment to indicate start of (new) function
            out += "/" + "*" * 79 + "\n"
            out += f"* {func_name}" + "\n"
            out += "*" * 79 + f"/" + "\n\n"
            out += "".join(arg_recorders)

        return jsbeautifier.beautify(out)

    def _generate_dispatchers(self, func: Cursor, args: List[Cursor]):

        body = fs.dispatcher_body_case(func.spelling, args)
        for idx, arg in enumerate(args):
            # check if the first param is a C `this` reference and skip it.
            # fptr struct members often take the sorrounding struct as the first
            # parameter to mimic OOP.
            if (
                idx == 0
                and arg
                and self._definition.type.spelling in arg.type.spelling
            ):
                continue

            # before, when collecting the params for CPP methods, we add a
            # `None` param representing the `this` reference
            if idx == 0 and arg is None:
                continue

            body += fs.dispatcher_body_case_arg(func.spelling, arg)
        body += "break;\n"
        return body

    def _generate_param_recorders(
        self, func: Cursor, args: List[Cursor]
    ) -> List[str]:
        """Generate a `List` of js functions (`str`) to record the `args` of
           `func` using Frida.

        Args:
            func (Cursor): The function we hook into using Frida.
            args (List[Cursor]): The arguments we generate recorders for.

        Returns:
            List[str]: `List` of js code (`str`), each code snippet representing
                       a recorder for one of the parameters in `func`.
        """

        param_recorders: List[str] = []
        self._current_args = args
        self._current_function = func
        for idx, arg in enumerate(args):

            # check if the first param is a `this` reference and skip it
            if (
                idx == 0
                and arg
                and self._definition.type.spelling in arg.type.spelling
            ):
                continue

            if idx == 0 and arg is None:
                continue

            self._current_record = None
            self._current_arg_idx = idx
            self._current_arg_name = arg.spelling
            self._current_parent = arg
            self._current_primitive_name = arg.spelling
            jscode: List[str] = []

            log.info(f"Processing param {arg.spelling} of type {arg.type.spelling}")

            open_arg_ctx_js = fs.call_open_arg_ctx(
                func.spelling, arg.spelling, arg.type.spelling
            )
            close_arg_ctx_js = fs.call_close_arg_ctx(
                func.spelling, arg.spelling, arg.type.spelling
            )

            res, snippet = self._traverse_type(arg.type)

            assert (
                res == 0
            ), f"traversing type {arg.type.spelling} ({arg.type.kind}) failed"

            jscode.append(open_arg_ctx_js)
            jscode.append("var v0 = arg;")
            jscode.append(snippet)
            jscode.append(close_arg_ctx_js)

            recorder_snippet = fs.record_param(
                func.spelling, arg.spelling, "".join(jscode)
            )
            # recorder_snippet = jsbeautifier.beautify(recorder_snippet)
            param_recorders.append(recorder_snippet)
        return param_recorders

    def _traverse_type(self, type: Type):

        log.info(f"Type is `{type.spelling}` ({type.kind})")

        if type.is_const_qualified():
            decl = type.get_declaration()
            type = decl.type

            # TODO: is this the right way to "de-constify"?
            # _type = type
            # type = type.get_named_type()

            #assert type.spelling in _type.spelling, "de-constification failed"
            assert (
                "const" not in type.spelling
            ), "de-constification failed, still const"

        if type.kind == TypeKind.VOID:
            # cannot do much with a void type
            return 0, "// Return type is  `void`"

        if type.kind == TypeKind.ELABORATED:
            return self._traverse_type(type.get_canonical())
        elif type.kind == TypeKind.UNEXPOSED:
            # this is usually the case for template records in CPP
            canonical_type = type.get_canonical()
            return self._traverse_type(canonical_type)
        elif type.kind == TypeKind.POINTER:
            return self._traverse_pointer(type)
        elif type.kind == TypeKind.TYPEDEF:
            return self._traverse_typedef(type)
        elif type.kind == TypeKind.CONSTANTARRAY:
            return self._traverse_constarray(type)
        elif type.kind in PRIMITIVE_TYPES or type.kind == TypeKind.ENUM:
            jscode = []
            jscode.append(fs.call_marshal_scalar("v0", "v0", type.get_size()))
            jscode.append(
                fs.call_marshal_param(
                    self._current_function.spelling,
                    self._current_arg_name,
                    self._current_parent.spelling,
                    type.spelling,
                )
            )
            return 0, "\n".join(jscode)
        elif type.kind == TypeKind.RECORD:
            return self._traverse_record(type)
        elif type.kind == TypeKind.LVALUEREFERENCE:
            # pass-by-reference semantics in cpp
            jscode = []
            pointee = type.get_pointee()
            jscode.append(f"var sz = {pointee.get_size()}")
            jscode.append(fs.call_deref_pointer("v0", "v0", "sz"))
            status, js = self._traverse_type(pointee)
            if status:
                raise IntrospectionException("Error handling LVALUEREF array.")
            jscode.append(js)
            return 0, "\n".join(jscode)
        elif type.kind == TypeKind.FUNCTIONPROTO:
            # fargs = collect_fptr_args(f)
            # self._functions[f].extend(fargs)
            raise (NotImplementedError(f"type {type.kind} not implemented"))
        elif type.kind == TypeKind.INCOMPLETEARRAY:
            # ignore incomplete arrays
            return 0, f"// `{type.spelling}` ({type.kind}) ignored"
        else:
            import ipdb

            ipdb.set_trace()
            raise (NotImplementedError(f"type {type.kind} not implemented"))

    def _traverse_record(self, type: Type):

        self._current_record_depth += 1
        depth = self._current_record_depth

        # store the record assigned by our callers
        prev_record = self._current_record
        # this record is the current record context now
        self._current_record = type

        jscode = []

        open_record_ctx_js = fs.call_open_record_ctx(
            self._current_arg_name,
            self._current_record.spelling,
            self._current_parent.spelling,
        )
        jscode.append(open_record_ctx_js)
        jscode.append(f"var record_d{depth} = v0;")


        if type.get_num_template_arguments() > 0:
            # this is a template
            status, js =  self._traverse_template_record(type)
            if status:
                raise IntrospectionException("Error handling const array.")
            jscode.append(js)

            # if type.get_size() <= 0:
            #     import ipdb

            #     ipdb.set_trace()
            # assert type.get_size() > 0, "Unexpected size of template record"

            # if len(list(type.get_fields())) <= 0:
            #     import ipdb

            #     ipdb.set_trace()

            # assert (
            #     len(list(type.get_fields())) > 0
            # ), "Expecting at least one field in this record"
        else:
            if len(list(type.get_fields())) == 0:
                raise IntrospectionException("#fields in record is 0")

            # save the field information
            prev_field_idx = self._current_field_idx
            prev_field_name = self._current_field_name

            for idx, field in enumerate(type.get_fields()):
                tmp_parent = self._current_parent
                self._current_parent = field

                # update the current field information
                self._current_field_idx = idx
                self._current_field_name = field.spelling

                field_size = field.type.get_size()
                assert field.get_field_offsetof() % 8 == 0

                offset = field.get_field_offsetof() // 8

                if field.type.get_declaration().kind == CursorKind.UNION_DECL:
                    slice_js = f"v0 = record_d{depth}.slice({offset}, {offset + field_size});"
                    jscode.append(slice_js)
                    status, js = self._traverse_union(field.type)
                    if status:
                        raise IntrospectionException("Error handling const array.")
                    jscode.append(js)
                else:
                    # TODO: do not slice here. slice at leaf node
                    slice_js = f"v0 = record_d{depth}.slice({offset}, {offset + field_size});"
                    jscode.append(slice_js)
                    # jscode.append("v0 = record;")
                    status, js = self._traverse_type(field.type)
                    if status:
                        raise IntrospectionException("Error handling const array.")
                    jscode.append(js)
                self._current_parent = tmp_parent

            # restore the field information
            self._current_field_idx = prev_field_idx
            self._current_field_name = prev_field_name

        close_record_ctx_js = fs.call_close_record_ctx(
            self._current_arg_name, self._current_record.spelling
        )
        jscode.append(close_record_ctx_js)
        # restore the record assigned from our callers
        self._current_record = prev_record

        self._current_record_depth -= 1
        return 0, "\n".join(jscode)

    def _traverse_template_record(self, type: Type):
        assert (
            type.get_num_template_arguments() > 0
        ), f"{type.spelling} is not a template"

        jscode = []

        depth = self._current_record_depth
        jscode.append(f"var record_d{depth} = v0;")

        if type.get_declaration().spelling == "vector":
            status, js = self._travese_template_vector(type)
            if status:
                raise IntrospectionException("Error handling template vector.")
            jscode.append(js)
        elif type.get_declaration().spelling == "function":
            status, js = self._traverse_template_function(type)
            if status:
                raise IntrospectionException("Error handling template function.")
            jscode.append(js)
        elif type.get_declaration().spelling == "hidl_vec":
            log.info("hidl_vec")
            status, js = self._travese_template_hidl_vec(type)
            if status:
                raise IntrospectionException("Error handling template hidl_vec.")
            jscode.append(js)
        elif type.get_declaration().spelling == "hidl_array":
            log.info("hidl_array")
            status, js = self._travese_template_hidl_array(type)
            if status:
                raise IntrospectionException("Error handling template hidl_array.")
            jscode.append(js)
        elif type.get_declaration().spelling in ["basic_string", "sp", "Return", "hidl_pointer"]:
            # ignore some irrelevant templates
            # std::__cxx11::basic_string<T>
            # android::sp<T>
            # android::hardware::Return<T>
            # android::hardware::details::hidl_pointer<T>
            pass
        else:
            import ipdb; ipdb.set_trace()
            raise NotImplementedError(f"Template {type.spelling} no implemented")
        return 0, "\n".join(jscode)

    def _traverse_template_function(self, type: Type):
        jscode = []

        assert (
            type.get_num_template_arguments() == 1
            and type.get_template_argument_type(0).kind
            == TypeKind.FUNCTIONPROTO
        ), "Error traversing template function"

        cb_func = self._current_args[self._current_arg_idx].type.get_declaration()
        sanity_check_cursor = cb_func.underlying_typedef_type.get_canonical().get_declaration()
        assert (sanity_check_cursor.type.spelling == type.spelling), "Type names do not match"

        fargs = collect_fptr_args(cb_func)
        self._functions_wq.append((cb_func, fargs))
        jscode.append(fs.intercept_function_pointer(cb_func.spelling, self._current_arg_name))

        return 0, "\n".join(jscode)


    def _travese_template_vector(self, type: Type):
        template_argument_type = type.get_template_argument_type(0)
        sz = template_argument_type.get_size()
        depth = self._current_record_depth

        jscode = []
        # slice start pointer as int from the record
        jscode.append(
            f"var vec_start{depth} = arrayToInt(record_d{depth}.slice(0, {POINTER_SZ}));"
        )
        jscode.append(f"console.log('start: ' + vec_start{depth});")

        # slice end pointer as int from the record
        jscode.append(
            f"var vec_end{depth} = arrayToInt(record_d{depth}.slice({POINTER_SZ}, {2*POINTER_SZ}));"
        )
        jscode.append(f"console.log('end: ' + vec_start{depth});")

        # calc current sz
        jscode.append(f"var vec_sz{depth} = vec_end{depth} - vec_start{depth};")


        if template_argument_type.kind in PRIMITIVE_TYPES or sz in [
            1,
            2,
            4,
        ]:
            jscode.append(f"v0 = ptr(vec_start{depth});")
            jscode.append(fs.call_deref_pointer("v0", "v0", f"vec_sz{depth}"))
            jscode.append(
                fs.call_marshal_param(
                    self._current_function.spelling,
                    self._current_arg_name,
                    self._current_parent.spelling,
                    self._current_parent.type.spelling,
                )
            )
        else:
            jscode.append(
                    f"for (var i = 0; i*{sz} < vec_sz{depth}; i++) {{"
            )
            jscode.append(f"v0 = ptr(vec_start{depth} + i*{sz});")
            jscode.append(fs.call_deref_pointer("v0", "v0", sz))
            status, js = self._traverse_type(template_argument_type)

            if status:
                raise IntrospectionException("Error traversing vector templatej specialization.")
            jscode.append(js)

            jscode.append(
                    f"}}"
            )
        return 0, "\n".join(jscode)

    def _travese_template_hidl_vec(self, type: Type):
        template_argument_type = type.get_template_argument_type(0)
        sz = template_argument_type.get_size()
        depth = self._current_record_depth

        jscode = []
        #jscode.append(fs.hexdump(f"record_d{depth}", 4*POINTER_SZ))
        jscode.append(f"var mBuffer_{depth} = arrayToInt(record_d{depth}.slice(0, {POINTER_SZ}));")
        jscode.append(f"var mSize_{depth} = arrayToInt(record_d{depth}.slice({POINTER_SZ}, {POINTER_SZ+4}));")
        # jscode.append(f"console.log('mBuffer_{depth}: ' + ptr(mBuffer_{depth}));")
        # jscode.append(f"console.log('mSize_{depth}: ' + mSize_{depth});")

        if template_argument_type.kind in PRIMITIVE_TYPES or sz in [
            1,
            2,
            4,
        ]:
            jscode.append(f"v0 = ptr(mBuffer_{depth});")
            jscode.append(fs.call_deref_pointer("v0", "v0", f"mSize_{depth}"))
            jscode.append(
                fs.call_marshal_param(
                    self._current_function.spelling,
                    self._current_arg_name,
                    self._current_parent.spelling,
                    self._current_parent.type.spelling,
                )
            )
        else:
            jscode.append(
                    f"for (var i = 0; i*{sz} < mSize_{depth}; i++) {{"
            )
            jscode.append(f"v0 = ptr(mBuffer_{depth} + i*{sz});")
            jscode.append(fs.call_deref_pointer("v0", "v0", sz))
            status, js = self._traverse_type(template_argument_type)

            if status:
                raise IntrospectionException("Error traversing vector template specialization.")
            jscode.append(js)

            jscode.append(
                    f"}}"
            )
        return 0, "\n".join(jscode)

    def _travese_template_hidl_array(self, type: Type):
        template_argument_type = type.get_template_argument_type(0)
        sz = template_argument_type.get_size()
        depth = self._current_record_depth

        jscode = []
        jscode.append("console.log('foobarbaz');")
        # jscode.append(fs.hexdump(f"record_d{depth}", 4*POINTER_SZ))
        jscode.append(f"var mBuffer_{depth} = arrayToInt(record_d{depth}.slice(0, {POINTER_SZ}));")
        jscode.append(f"var mSize_{depth} = arrayToInt(record_d{depth}.slice({POINTER_SZ}, {POINTER_SZ+4}));")
        jscode.append(f"console.log('mBuffer_{depth}: ' + ptr(mBuffer_{depth}));")
        jscode.append(f"console.log('mSize_{depth}: ' + mSize_{depth});")
        return 0, "\n".join(jscode)

        if template_argument_type.kind in PRIMITIVE_TYPES or sz in [
            1,
            2,
            4,
        ]:
            jscode.append(f"v0 = ptr(mBuffer_{depth});")
            jscode.append(fs.call_deref_pointer("v0", "v0", f"mSize_{depth}"))
            jscode.append(
                fs.call_marshal_param(
                    self._current_function.spelling,
                    self._current_arg_name,
                    self._current_parent.spelling,
                    self._current_parent.type.spelling,
                )
            )
        else:
            jscode.append(
                    f"for (var i = 0; i*{sz} < mSize_{depth}; i++) {{"
            )
            jscode.append(f"v0 = ptr(mBuffer_{depth} + i*{sz});")
            jscode.append(fs.call_deref_pointer("v0", "v0", sz))
            status, js = self._traverse_type(template_argument_type)

            if status:
                raise IntrospectionException("Error traversing vector template specialization.")
            jscode.append(js)

            jscode.append(
                    f"}}"
            )
        return 0, "\n".join(jscode)


    def _traverse_union(self, type: Type):

        # for unions, we have the case in mind where the union is a member of a struct
        assert (
            self._current_parent.kind == CursorKind.FIELD_DECL
        ), "UNION member not a FIELD_DECL, is this union part of a RECORD?"

        # if self._current_parent.type.kind != TypeKind.ELABORATED:
        #     import ipdb; ipdb.set_trace()

        # assert (
        #     self._current_parent.type.kind == TypeKind.ELABORATED
        # ), "type of this FIELD_DECL node is expected to be ELABORATED"

        assert (
            type.get_declaration().kind == CursorKind.UNION_DECL
        ), "declaration is not a UNION_DECL"

        p = self._search_pointer(type)
        jscode = []
        # save the union slice
        jscode.append(f"var union_slice = v0;")
        if p is not None:
            # the union contains pointer members but we do not know
            # if it is actually used as a pointer.
            # our heuristic is to see if it points to rw memory.
            pointee = p.get_pointee()

            # the pointer is aligned to `PTR_SZ` and starts at offset 0 in the
            # union. Thus, we slice `PTR_SZ` from this chunk of memory.
            jscode.append(f"var ptr_field = union_slice.slice(0, {POINTER_SZ});")
            pointee_deref_js = fs.call_deref_pointer(
                "ptr_field", "v0", pointee.get_size()
            )
            jscode.append(pointee_deref_js)

            status, traverse_pointee_js = self._traverse_type(pointee)
            if status:
                raise IntrospectionException("Error handling const array.")
            jscode.append(f"if (v0){{ {traverse_pointee_js} }}")

            jscode.append("else {")
            # otherwise, take the union's memory

            jscode.append(f"v0 = union_slice;")
            jscode.append(
                fs.call_marshal_param(
                    self._current_function.spelling,
                    self._current_arg_name,
                    self._current_parent.spelling,
                    type.spelling,
                )
            )
            jscode.append("}")
        else:
            jscode.append(f"v0 = union_slice;")
            jscode.append(
                fs.call_marshal_param(
                    self._current_function.spelling,
                    self._current_arg_name,
                    self._current_parent.spelling,
                    type.spelling,
                )
            )
        return 0, "\n".join(jscode)

    def _traverse_constarray(self, type: Type):
        elem_type = type.get_array_element_type()
        sz = elem_type.get_size()
        n = type.get_array_size()

        jscode = []

        js_open_array_ctx = fs.call_open_array_ctx(
            self._current_arg_name, type.spelling, self._current_parent.spelling
        )
        jscode.append(js_open_array_ctx)
        jscode.append(f"var arr_base = v0;")
        for idx in range(n):
            jscode.append(f"v0 = arr_base.slice({idx*sz});")
            status, js = self._traverse_type(elem_type)
            if status:
                raise IntrospectionException("Error handling const array.")
            jscode.append(js)
        js_close_array_ctx = fs.call_close_array_ctx(
            self._current_arg_name, type.spelling
        )
        jscode.append(js_close_array_ctx)
        return 0, "\n".join(jscode)

    def _traverse_pointer(self, type: Type):

        pointee = type.get_pointee()
        type_sz = pointee.get_size()

        if pointee.kind == TypeKind.VOID:
            return 0, f"// deref of `{type.spelling}` is not supported"
        elif type_sz <= 0:
            return -1, f"// cannot deref `{type.spelling}` of size {type_sz}"

        pointer_sz_prep = f"var sz{self._current_record_depth} = {type_sz};\n"

        if self._current_record:
            # we are inside of a record and this field is a pointer
            if self._neighboring_field_is_size():
                # the next field is a length indicator for the current field
                field = self._lookahead_field()
                # this is the offset within the record where to find it
                offset = field.get_field_offsetof() // 8

                jscode = []
                jscode.append(f"var sz{self._current_record_depth} = record_d{self._current_record_depth}.slice({offset}, {offset + field.type.get_size()});")
                jscode.append(f"sz{self._current_record_depth} = arrayToInt(sz{self._current_record_depth});")
                jscode.append(f"console.log('sz{self._current_record_depth} is ' + sz{self._current_record_depth})")

                ret, pointee_out = self._traverse_type(pointee)

                if ret != 0:
                    return -1, f"// error processing {pointee.spelling}"

                if not self._search_pointer(pointee):
                    jscode.append(f"var array_base{self._current_record_depth} = v0;")
                    jscode.append(
                        f"v0 = Memory.readByteArray(ptr(arrayToInt(array_base{self._current_record_depth})), sz{self._current_record_depth}*{pointee.get_size()});"
                    )
                    jscode.append(
                        fs.call_marshal_param(
                            self._current_function.spelling,
                            self._current_arg_name,
                            self._current_parent.spelling,
                            type.spelling,
                        )
                    )
                else:
                    jscode.append(f"var array_base{self._current_record_depth} = v0;")
                    jscode.append(f"for (var i{self._current_record_depth} = 0; i{self._current_record_depth} < parseInt(sz{self._current_record_depth}); i{self._current_record_depth}++) {{")
                    jscode.append(f"v0 = ptr(arrayToInt(array_base{self._current_record_depth}) + ({pointee.get_size()}*i{self._current_record_depth}))")
                    jscode.append(fs.call_deref_pointer("v0", "v0", f"{pointee.get_size()}"))
                    jscode.append(pointee_out)
                    jscode.append(f"}}")

                return 0, "\n".join(jscode)
        elif self._neighboring_param_is_size():
            next_param = self._lookahead_param()
            if next_param:
                prep_sz_param = f"var sz{self._current_record_depth} = args[{self._current_arg_idx + 1}];"
                # we consider two scenarios here. (1) the neighboring param is a
                # scalar, or (2) it is a pointer to a scalar.
                ret, snippet = self._traverse_scalar(next_param.type)
                if ret == 0:
                    pointer_sz_prep = prep_sz_param + snippet

        if pointee.kind == TypeKind.POINTER:
            # pointer to pointer case
            # pointer_sz_prep = fs.call_deref_pointer("v0", "v0", POINTER_SZ)
            pointee_pointee = pointee.get_pointee()
            type_sz = pointee_pointee.get_size()
            if type_sz <= 0:
                return (
                    -1,
                    f"// cannot deref `{pointee_pointee.spelling}` of size {type_sz}",
                )

        # pointer_sz_prep += f"sz = sz * {type_sz};"
        out = pointer_sz_prep + fs.call_deref_pointer("v0", "v0", f"sz{self._current_record_depth}")
        log.info(f"pointee: {pointee.spelling}")
        ret, pointee_out = self._traverse_type(pointee)
        return ret, out + pointee_out

    @staticmethod
    def _search_pointer(type: Type) -> Type:
        """Traverses `type` for pointers. Returns the `Type` object of this
        pointer, if it exists. If it does not exit, `None` is returend.

        Args:
            type (Type): The type to check for pointers.

        Returns:
            Optional(Type): Returns the pointer `Type` object or `None`.
        """

        pointer = None
        if type.kind == TypeKind.ELABORATED:
            pointer = IntrospectionRecorderGenerator._search_pointer(
                type.get_canonical()
            )
        elif type.kind == TypeKind.RECORD:
            for field in type.get_fields():
                pointer = IntrospectionRecorderGenerator._search_pointer(
                    field.type
                )
                if pointer:
                    break
        elif type.kind == TypeKind.POINTER:
            pointer = type
        elif type.kind in PRIMITIVE_TYPES:
            None
        elif type.kind == TypeKind.ENUM:
            return None
        elif type.kind == TypeKind.TYPEDEF:
            typedef_type = type.get_declaration().underlying_typedef_type
            return IntrospectionRecorderGenerator._search_pointer(typedef_type)
        else:
            raise NotImplementedError(
                "Implement me! TypeKind: {}".format(type.kind)
            )
        return pointer

    def _traverse_scalar_pointer(self, type: Type):
        pointee = type.get_pointee()
        sz = pointee.get_size()
        return 0, fs.call_deref_pointer("sz", "sz", sz)

    def _traverse_scalar(self, type: Type):
        log.info(f"Scalar (pointer) type is `{type.spelling}`")

        if type.kind == TypeKind.VOID:
            # cannot do much with a void type
            return -1, "// Cannot record void type"

        if type.is_const_qualified():
            decl = type.get_declaration()
            _type = type
            type = decl.type
            assert type.spelling in _type.spelling, "de-constification failed"
            assert (
                "const" not in type.spelling
            ), "de-constification failed, still const"

        if type.kind == TypeKind.POINTER:
            return self._traverse_scalar_pointer(type)
        elif type.kind == TypeKind.ELABORATED:
            return self._traverse_type(type.get_canonical())
        elif type.kind == TypeKind.TYPEDEF:
            return self._traverse_typedef(type)
        elif type.kind in PRIMITIVE_TYPES:
            return 0, fs.call_marshal_scalar("sz", type.get_size())
        else:
            import ipdb

            ipdb.set_trace()

    def _lookahead_param(self) -> Optional[Cursor]:
        """Return a `Cursor` to the next param, or `None` if there is no next
        param."""
        lookahead_idx = self._current_arg_idx + 1
        if len(self._current_args) > lookahead_idx:
            return self._current_args[lookahead_idx]
        return None

    def _neighboring_param_is_size(self) -> bool:
        """Return `True` if the next parameter is a size-indicating parameter,
           return `False` otherwise.

        While processing a function, we keep track of the current parameter in
        `self._current_arg_idx`. This function checks if the paramter with index
        `self._current_arg_idx + 1`, if existent, is a size-indicating parameter
        based on some heuristics.

        Returns:
            bool: `True` if next param is size, `False` otherwise.
        """
        ret = False
        arg = self._lookahead_param()
        if arg and self._contains_size_keyword(arg.spelling):
            ret = True
        return ret

    def _lookahead_field(self) -> Optional[Cursor]:
        """Return a `Cursor` to the next param, or `None` if there is no next
        param."""
        lookahead_idx = self._current_field_idx + 1
        fields = list(self._current_record.get_fields())
        if len(fields) > lookahead_idx:
            return fields[lookahead_idx]
        return None

    def _neighboring_field_is_size(self) -> bool:
        ret = False
        field = self._lookahead_field()
        if field and self._contains_size_keyword(field.spelling):
            ret = True
        return ret

    def _contains_size_keyword(self, s: str) -> bool:
        """Return `True` if `s` contains size-indicating keywords, `False`
        otherwise."""

        return any([True for keyword in LENGTH_KEYWORDS if keyword in s.lower()])

    def _traverse_typedef(self, type: Type):
        typedef_type = type.get_declaration().underlying_typedef_type
        return self._traverse_type(typedef_type)