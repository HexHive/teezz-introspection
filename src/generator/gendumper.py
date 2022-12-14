#!/usr/bin/env python
import sys
import logging
import jsbeautifier
from collections import OrderedDict
from .functiondumper import FunctionDumper, CB_FUNCTIONS

import clang.cindex
from clang.cindex import Index, CursorKind, TypeKind, Diagnostic, Type

# project-global log configuration
logging.basicConfig(
    format="%(asctime)s,%(msecs)d %(levelname)-8s "
    "[%(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
)

# module-local log setup
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def collect_functions(definition):
    """Collect all functions in the given definition.

    returns a list to of clang.cindex.Cursor objects to functions within the given `definition`."""

    functions = []
    # iterate over definition's members
    for node in definition.get_children():
        if (
            node.type.kind == TypeKind.POINTER
            and node.type.get_pointee().kind == TypeKind.FUNCTIONPROTO
        ):
            functions.append(FunctionDumper(node))
        elif (
            node.type.kind == TypeKind.FUNCTIONPROTO
            and node.kind == CursorKind.CXX_METHOD
            and "operator" not in node.spelling
        ):
            # log.debug("##### {} ({}) of type {} ({}) of def {}".format(node.spelling, node.kind, node.type.spelling, node.type.kind, node.type.get_declaration()))
            functions.append(FunctionDumper(node))
    return functions


def find_hal_cursor(cursor, cursor_spelling):
    """Recurse TU until we find the cursor containing the sub-tree of the AST we are intersted in.

    In C, this is usually a `CursorKind.STRUCT_DECL`.
    In CPP, this is either a `CursorKind.STRUCT_DECL` or a `CursorKind.CLASS_DECL`.
    """
    if (
        cursor.kind in [CursorKind.STRUCT_DECL, CursorKind.CLASS_DECL]
        and cursor_spelling == cursor.spelling
    ):
        return cursor.type.get_declaration().get_definition()
    for c in cursor.get_children():
        ret = find_hal_cursor(c, cursor_spelling)
        if ret:
            return ret
    return None


def parse(tu_path, clang_args):
    """Let clang parse the source code and return the tu object. Returns `None` if errors occur."""
    index = clang.cindex.Index.create()
    tu = index.parse(tu_path, clang_args)

    # check the diagnostics if something went wrong
    diagnostics = [d for d in tu.diagnostics]
    if len(diagnostics) > 0:
        should_terminate = False
        for d in diagnostics:
            log.warn(d)
            #if d.severity >= Diagnostic.Error:
            #    should_terminate = True
        if should_terminate:
            import ipdb

            ipdb.set_trace()
            log.error("Error parsing translation unit.")
            return None
    return tu


def emit_js(cursor):
    """Returns the Frida js code for the dumper as a `str`."""

    # collect all functions
    functions = collect_functions(cursor)
    jscode = []

    # generate regular dump functions
    for function in functions:
        jscode.append(function.emit_frida_code())
    # generate dump functions for callbacks
    for function in CB_FUNCTIONS:
        jscode.append(function.emit_frida_code())

    # generate dispatcher
    jscode.append("function dump(fname, args, saved_args, ret, dump_id){\n")
    jscode.append("  switch(fname){\n")

    for function in functions:
        jscode.append(function.dispatcher())
    for function in CB_FUNCTIONS:
        jscode.append(function.dispatcher())

    jscode.append("  }\n}")

    return jsbeautifier.beautify("\n".join(jscode))


def find_std_func(cursor, spelling):
    if "_M_invoker" in cursor.spelling:
        print(cursor.spelling)
        import ipdb

        ipdb.set_trace()
        return None
    for c in cursor.get_children():
        ret = find_std_func(c, spelling)
        if ret:
            return ret
    return None


def main(cursor_spelling, tu_path, clang_args):
    log.info(f"Parsing {tu_path}")
    log.info(f"Args {clang_args}")
    try:
        tu = parse(tu_path, clang_args)
    except clang.cindex.TranslationUnitLoadError as e:
        log.error(e)
        import ipdb; ipdb.set_trace()

    if not tu:
        log.error(f"Error parsing {tu_path}")
        sys.exit(-1)

    # spelling = "std::function<void (bool)>"
    # find_std_func(tu.cursor, spelling)

    # find the cursor that we are looking for
    cursor = find_hal_cursor(tu.cursor, cursor_spelling)
    if not cursor:
        log.error(f"{cursor_spelling} not found in TU")
        sys.exit(-1)

    print(emit_js(cursor))


def usage():
    print(
        "{} <struct_name> <header_file> [<clang_options>]".format(sys.argv[0])
    )
    print("\nE.g.:")
    print('\t{} "struct keymaster1_device" km.hpp'.format(sys.argv[0]))
    print('\t{} "struct gatekeeper_device" gk.hpp'.format(sys.argv[0]))
    print('\t{} "struct fingerprint_device" fp.hpp'.format(sys.argv[0]))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()
        sys.exit(0)

    main(sys.argv[1], sys.argv[2], sys.argv[3:])
