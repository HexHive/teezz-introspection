import clang.cindex
from clang.cindex import (
    CursorKind,
    TypeKind,
    Diagnostic,
    Cursor,
    Type,
    TranslationUnit,
)
import logging

################################################################################
# TYPING
################################################################################

from typing import Tuple, List, Optional

################################################################################
# MONKEY PATCHING
################################################################################


def cursor_hash(self: Cursor):
    return self.hash


def type_hash(self: Type):
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

PRIMITIVE_TYPES = [
    TypeKind.BOOL,
    TypeKind.UCHAR,
    TypeKind.CHAR_S,
    TypeKind.USHORT,
    TypeKind.SHORT,
    TypeKind.UINT,
    TypeKind.INT,
    TypeKind.ULONG,
    TypeKind.LONG,
]

################################################################################
# CODE
################################################################################


def parse(tu_path: str, clang_args: List[str]) -> Optional[TranslationUnit]:
    """Let clang parse the source code and return the tu object. Returns `None` if errors occur."""

    index = clang.cindex.Index.create()
    tu = index.parse(tu_path, clang_args)

    # check the diagnostics if something went wrong
    for d in tu.diagnostics:
        log.warn(d)
        # abort if we encounter an error
        if d.severity >= Diagnostic.Error:
            log.error("Error parsing translation unit.")
            return None

    return tu


def get_definition(node: Cursor, def_spelling: str) -> Optional[Cursor]:
    """Traverse `node` and find the definition corresponding to
    `def_spelling`. Return the cursor to this definition if found and `None`
    otherwise.

    In C, we look for a `CursorKind.STRUCT_DECL` of type `TypeKind.RECORD`.
    In CPP, we look for either a `CursorKind.STRUCT_DECL` or a
    `CursorKind.CLASS_DECL` of type `TypeKind.RECORD`.

    TODO: Parametirize this function with the cursor and type we want to match.
    """

    if (
        node.kind
        in [CursorKind.TYPE_REF, CursorKind.STRUCT_DECL, CursorKind.CLASS_DECL]
        and node.type.kind == TypeKind.RECORD
        and def_spelling in node.spelling
    ):
        log.debug("got it!")
        return node.type.get_declaration().get_definition()
    for c in node.get_children():
        # recurse
        ret = get_definition(c, def_spelling)
        if ret:
            return ret
    return None


def collect_fptrs(definition: Cursor) -> List[Cursor]:
    """Collect all function pointer children of `definition`."""

    fptrs: List[Cursor] = []
    # iterate over definition's members
    for node in definition.get_children():

        log.debug(
            '##### {} ({}) of type {} ({}) of def "{}"'.format(
                node.spelling,
                node.kind,
                node.type.spelling,
                node.type.kind,
                node.type.get_declaration().spelling,
            )
        )

        # collect function pointers within C structs
        # in C, a function pointer as a member of a struct appears as a
        # `TypeKind.POINTER` to a `TypeKind.FUNCTIONPROTO``
        if node.type.kind == TypeKind.POINTER and (
            node.type.get_pointee().kind == TypeKind.UNEXPOSED
            or node.type.get_pointee().kind == TypeKind.FUNCTIONPROTO
        ):
            log.debug(
                "##### {} ({}) of type {} ({}) of def {}".format(
                    node.spelling,
                    node.kind,
                    node.type.spelling,
                    node.type.kind,
                    node.type.get_declaration(),
                )
            )
            fptrs.append(node)

        # collect function pointers within CPP classes
        # in CPP, a function pointer within a class appears as a
        # `CursorKind.CXX_METHOD` of type `TypeKind.FUNCTIONPROTO`
        if (
            node.kind == CursorKind.CXX_METHOD
            and node.type.kind == TypeKind.FUNCTIONPROTO
        ):
            fptrs.append(node)
    return fptrs


def collect_fptr_args(fptr: Cursor) -> List[Cursor]:
    """Return a list of `Cursor`s each pointing to a parameter of
    `fptr`"""

    args: List[Cursor] = []
    if fptr.kind == CursorKind.CXX_METHOD:
        # add the `this` parameter for CPP methods
        args.append(None)

    if (fptr.kind == CursorKind.TYPE_ALIAS_DECL
        and fptr.underlying_typedef_type.get_canonical()
        .get_template_argument_type(0).kind == TypeKind.FUNCTIONPROTO):
        # this is the template callback case
        # add the `this` parameter, since we assume this is a CPP method

        # TODO: this break if the callback function does not have a `this`
        # reference as a first paramter. Check if `this` is requrired or not.
        args.append(None)

    for fptr_param in fptr.get_children():
        if fptr_param.kind == CursorKind.PARM_DECL:
            log.debug(
                "{} ({})".format(fptr_param.spelling, fptr_param.type.spelling)
            )
            args.append(fptr_param)
    return args
