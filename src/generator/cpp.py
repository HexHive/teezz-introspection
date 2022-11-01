#!/usr/bin/env python
from __future__ import print_function
import sys
import logging
import jsbeautifier
from collections import OrderedDict

from clang.cindex import Index, CursorKind, TypeKind, Diagnostic

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


type_info = OrderedDict({'fptr': OrderedDict(), 'enums': OrderedDict(), 'structs': OrderedDict()})

PRIMITIVE_TYPES = [
    TypeKind.BOOL,
    TypeKind.UCHAR,
    TypeKind.USHORT,
    TypeKind.UINT,
    TypeKind.ULONG
]

LENGTH_KEYWORDS = [
    'length',
    'len',
    'size',
    'size'
]


def handle_void(arg, field_type, definitions, varno, jscode, type_info=None, ilvl=1, is_array=False):
    return TypeKind.VOID, field_type.spelling


def handle_typedef(arg, field_type, definitions, varno, jscode, type_info=None, ilvl=1, is_array=False):
    typedef_type = field_type.get_declaration().underlying_typedef_type
    return handle_param(arg, typedef_type, definitions, varno, jscode, type_info, ilvl+1)


def handle_elaborated(arg, field_type, definitions, varno, jscode, type_info=None, ilvl=1, is_array=False):
    return handle_param(arg, field_type.get_canonical(), definitions, varno, jscode, type_info, ilvl+1)


def handle_constantarray(arg, field_type, definitions, varno, jscode, type_info=None, ilvl=1, is_array=False):
    #field_type.get_array_element_type().kind
    # TypeKind.TYPEDEF
    #field_type.get_array_element_type().spelling
    # 'uint8_t'
    sz = field_type.get_array_element_type().get_size()
    n = field_type.get_array_size()

    jscode.append(ilvl*"  " + "// It's a CONSTANTARRAY!")
    jscode.append(ilvl*"  " + "var dump = Memory.readByteArray(v{}, {});".format(varno, sz*n))
    jscode.append(ilvl*"  " + "send({{ 'type' : 'dump', 'on_enter': is_onenter, 'arg' : '{}', 'data_type' : '{}', 'dump_id': DUMP_ID  }}, dump);".format(arg['spelling'], field_type.spelling))
    return TypeKind.CONSTANTARRAY, field_type.spelling


def handle_lvaluereference(arg, field_type, definitions, varno, jscode, type_info=None, ilvl=1, is_array=False):
    record = field_type.get_pointee().get_declaration().type.get_declaration()

    mBuffer = list(record.type.get_fields())[0].type
    # hidl_pointer is defined in libhidl/base/include/hidl/HidlInternal.h
    #  call get_canonical() to get underlying type
    mBuffer = mBuffer.get_canonical()

    field_decl = list(mBuffer.get_fields())[0]  # this is the union declaration inside of the hidl_pointer struct
    mPointer = list(field_decl.type.get_fields())[0]

    jscode.append("  if(arg == 0 || arg == undefined){ return; };")
    jscode.append("  var visited_ptrs = new Array();")

    jscode.append("  var hidl_len = get_hidl_vec_size(arg);")
    jscode.append("  var mBuffer = Memory.readPointer(arg);")
    jscode.append("  var elem_size = {};".format(mPointer.type.get_pointee().get_size()))
    jscode.append("  for (var i = 0; i<parseInt(hidl_len); i++) {")

    # Here we need to handle the elements
    jscode.append("    var v0 = ptr(mBuffer).add(elem_size * i);")
    handle_param(arg, mPointer.type.get_pointee(), definitions, 0, jscode, type_info=type_info, ilvl=2)

    jscode.append("  }\n")

    return TypeKind.LVALUEREFERENCE, field_type.spelling


def handle_enum(arg, field_type, definitions, varno, jscode, type_info=None, ilvl=1, is_array=False):
    jscode.append(ilvl*"  " + "// enum {}".format(field_type.spelling))
    jscode.append(ilvl*"  " + "var dump = Memory.readByteArray(v{}, {});".format(varno, field_type.get_size()))
    jscode.append(ilvl*"  " + "send({{ 'type' : 'dump', 'on_enter': is_onenter, 'arg' : '{}', 'data_type' : '{}', 'dump_id': DUMP_ID  }}, dump);".format(arg['spelling'], field_type.spelling))
    if type_info and field_type.spelling not in type_info['enums']:
        type_info['enums'][field_type.spelling] = {}
        for c in field_type.get_declaration().get_children():
            type_info['enums'][field_type.spelling][c.spelling] = c.enum_value
    return TypeKind.ENUM, field_type.spelling


def handle_record(arg, field_type, definitions, varno, jscode, type_info=None, ilvl=1, is_array=False):
    jscode.append(ilvl*"  " + "// {}".format(field_type.spelling))
    #if type_info and field_type.spelling not in type_info['structs']:
    type_info['structs'][field_type.spelling] = {'fields': [], 'type': field_type}
    fields = field_type.get_fields()
    offset = 0
    ilvl += 1
    for field in fields:
        f = {}
        f['spelling'] = field.spelling
        f['type'] = field.type
        f['type_spelling'] = field.type.spelling
        type_info['structs'][field_type.spelling]['fields'].append(f)
        jscode.append(ilvl*"  " + "// {} {}".format(field.spelling, field.type.spelling))

        if field.type.kind == TypeKind.POINTER:
            # ptr case: if this is an array, get content of length field first (for now, take next member as length)
            jscode.append(ilvl*"  " + "// It's a POINTER!")
            jscode.append(ilvl*"  " + "var len = Memory.readU32(v{}.add({}));".format(varno, offset+field.type.get_size()))
            jscode.append(ilvl*"  " + "var v{} = v{}.add({});".format(varno+1, varno, offset))

            p = field.type.get_pointee()
            if p.get_size() == 1:
                jscode.append(ilvl*"  " + "var dump = Memory.readByteArray(Memory.readPointer(v{}), len);".format(varno+1))
                jscode.append(ilvl*"  " + "send({{ 'type' : 'dump', 'on_enter': is_onenter, 'arg' : '{}', 'data_type' : '{}', 'dump_id': DUMP_ID  }}, dump);".format(arg['spelling'], p.spelling))
            else:
                jscode.append(ilvl*"  " + "var vno_saved = v{};".format(varno+1))
                jscode.append(ilvl*"  " + "for(var i = 0; i < len; i++){")
                jscode.append(ilvl*"  " + "v{} = Memory.readPointer(vno_saved).add({}*i);".format(varno+1, p.get_size()))
                handle_param(arg, p, definitions, varno+1, jscode, type_info, ilvl+1, True)
                jscode.append(ilvl*"  " + "}")

        elif field.type.get_declaration().kind == CursorKind.UNION_DECL:
            # union case: take biggest member and just dump size
            jscode.append(ilvl*"  " + "// It's a UNION!")
            jscode.append(ilvl*"  " + "var var_tmp = v{}.add({});".format(varno, offset))
            jscode.append(ilvl*"  " + "var dump = Memory.readByteArray(var_tmp, {});".format(field.type.get_size()))
            jscode.append(ilvl*"  " + "send({{ 'type' : 'dump', 'on_enter': is_onenter, 'arg' : '{}', 'data_type' : '{}', 'dump_id': DUMP_ID  }}, dump);".format(arg['spelling'], field.type.spelling))
        else:
            # easiest case: no ptr members, no unions:
            jscode.append(ilvl*"  " + "// It's a EASY!")
            jscode.append(ilvl*"  " + "var v{} = v{}.add({});".format(varno+1, varno, offset))
            handle_param(arg, field.type, definitions, varno+1, jscode, type_info, ilvl+1)

        field_size = field.type.get_size()
        # TODO: this depends on this struct being __packed__ or not, doesn't it?
        #offset += field_size if not field_size % 8 else field_size + (field_size % 8)
        offset += field_size
    return TypeKind.RECORD, field_type.spelling


def handle_primitive(arg, field_type, definitions, varno, jscode, type_info=None, ilvl=1, is_array=False):
    jscode.append(ilvl*"  " + "// primitive type: {}".format(field_type.spelling))
    jscode.append(ilvl*"  " + "var dump = Memory.readByteArray(v{}, {});".format(varno, field_type.get_size()))
    jscode.append(ilvl*"  " + "send({{ 'type' : 'dump', 'on_enter': is_onenter, 'arg' : '{}', 'data_type' : '{}', 'dump_id': DUMP_ID  }}, dump);".format(arg['spelling'], field_type.spelling))
    return field_type.kind, field_type.spelling


def handle_pointer(arg, field_type, definitions, varno, jscode, type_info=None, ilvl=1, is_array=False):
    jscode.append(ilvl*"  " + "// {}".format(field_type.spelling))

    jscode.append(ilvl*"  " + "if(v{} == 0){{ return;}}".format(varno))
    if ilvl == 1:
        # It's already the ptr coming directly from args[i]
        jscode.append(ilvl*"  " + "var v{} = v{};".format(varno+1, varno))
    else:
        jscode.append(ilvl*"  " + "var v{} = Memory.readPointer(v{});".format(varno+1, varno))

    jscode.append(ilvl*"  " + "if(v{} == 0){{ return;}}".format(varno+1))

    jscode.append("  if(isInArray(v{}.toString(), visited_ptrs)){{ return; }}".format(varno+1))
    jscode.append("  visited_ptrs.push(v{}.toString());".format(varno+1))

    pointee = field_type.get_pointee()
    if is_array:
        jscode.append(ilvl*"  " + "v{} = v{}.add(i * {});".format(varno+1, varno+1, pointee.get_size()))

    if pointee.kind == TypeKind.POINTER:
        defs = list(definitions)
        defs.append(pointee.get_pointee().get_declaration().get_definition())

        return handle_param(arg, pointee, defs, varno+1, jscode, type_info, ilvl+1)
    elif pointee.kind == TypeKind.VOID:
        return
    elif pointee.kind == TypeKind.BOOL:
        return handle_param(arg, pointee, definitions, varno+1, jscode, type_info, ilvl+1)
    elif pointee.get_size() == 1 and not is_array:
        # read C string
        jscode.append(ilvl*"  " + "var dump = ptr(v{}).readCString();".format(varno))
        jscode.append(ilvl*"  " + "send({{ 'type' : 'dump', 'on_enter': is_onenter, 'arg' : '{}', 'data_type' : '{}', 'dump_id': DUMP_ID  }}, dump);".format(arg['spelling'], field_type.spelling))
    else:
        return handle_param(arg, pointee, definitions, varno+1, jscode, type_info, ilvl+1)


def handle_unexposed(arg, field_type, definitions, varno, jscode, type_info=None, ilvl=1, is_array=False):
    return handle_param(arg, field_type.get_canonical(), definitions, varno, jscode, type_info, ilvl)


def handle_param(arg, field_type, definitions, varno, jscode, type_info=None, ilvl=1, is_array=False):
    log.info("here: {} ({})".format(field_type.spelling, field_type.kind))
    if field_type.kind in PRIMITIVE_TYPES:
        return handle_primitive(arg, field_type, definitions, varno, jscode, type_info, ilvl)
    elif field_type.kind == TypeKind.ENUM:
        return handle_enum(arg, field_type, definitions, varno, jscode, type_info, ilvl)
    elif field_type.kind == TypeKind.ELABORATED:
        return handle_elaborated(arg, field_type, definitions, varno, jscode, type_info, ilvl)
    elif field_type.kind == TypeKind.CONSTANTARRAY:
        return handle_constantarray(arg, field_type, definitions, varno, jscode, type_info, ilvl)
    elif field_type.kind == TypeKind.LVALUEREFERENCE:
        return handle_lvaluereference(arg, field_type, definitions, varno, jscode, type_info, ilvl)
    elif field_type.kind == TypeKind.TYPEDEF:
        return handle_typedef(arg, field_type, definitions, varno, jscode, type_info, ilvl)
    elif field_type.kind == TypeKind.RECORD:
        return handle_record(arg, field_type, definitions, varno, jscode, type_info, ilvl)
    elif field_type.kind == TypeKind.POINTER:
        return handle_pointer(arg, field_type, definitions, varno, jscode, type_info, ilvl)
    elif field_type.kind == TypeKind.UNEXPOSED:
        return handle_unexposed(arg, field_type, definitions, varno, jscode, type_info, ilvl)
    elif field_type.kind == TypeKind.VOID:
        return
    else:
        import ipdb; ipdb.set_trace()
        raise NotImplementedError("Implement me!")


def process_fptrs(definition, fptrs):
    """ iterate fptrs and generate js code for FRIDA to dump parameters from memory. """
    definitions = [definition]
    jscode = []
    jscode.append(
        "function get_hidl_vec_size(hidlVec) {\n"
        "  var ptr1 = ptr(hidlVec);\n"
        "  var ptr2 = ptr1.add(Process.pointerSize);\n"
        "  return Memory.readU32(ptr2);\n"
        "}\n"
    )

    dump_funcs = {}
    for fname, args in fptrs.items():
        log.info("processing {}".format(fname))
        for i, arg in enumerate(args):

            if fname not in dump_funcs:
                dump_funcs[fname] = []

            dump_funcs[fname].append(arg)
            jscode.append("function dump_{}_{}(arg, args, is_onenter){{".format(fname, arg['spelling']))
            #jscode.append("  send({{ 'type' : 'init_dump', 'func' : '{}', 'arg' : '{}', 'dump_id': DUMP_ID}});".format(fname, arg['spelling']))
            jscode.append("  // processing {} ({})".format(arg['spelling'], arg['type'].kind))
            jscode.append("  var v0 = arg;")

            if arg['spelling'] == "_hidl_cb":
                # In this case we somehow need to handle the callback function
                # Probably we need to hook that function as well and extract the parameters similarly
                log.info("Handling callback function")
                # TODO
                jscode.append("  // TODO")
                #import ipdb; ipdb.set_trace()

            elif "Return" in arg['type'].spelling:
                # Do we need to extract the return values too?
                log.info("Handling return value")
                # TODO
                jscode.append("  // TODO")
                #import ipdb; ipdb.set_trace()

            elif arg['type'].kind in [
                TypeKind.ENUM,
                TypeKind.ELABORATED,
                TypeKind.CONSTANTARRAY,
                TypeKind.LVALUEREFERENCE,
                TypeKind.TYPEDEF,
                TypeKind.RECORD,
                TypeKind.POINTER,
                TypeKind.UNEXPOSED,
                TypeKind.VOID
             ] :
                handle_param(arg, arg['type'], definitions, 0, jscode, type_info=type_info, ilvl=2)

            else:
                log.error("We don't handle this type yet.")
                import ipdb; ipdb.set_trace()
                #raise NotImplementedError("Implement me!")

            jscode.append("}\n")

            log.debug("--> {} of type {} ({})".format(arg['spelling'], arg['type'].spelling, arg['type'].kind))

    # Generate dispatcher
    dispatcher = []
    dispatcher.append("function dump(fname, args, saved_args, ret){")
    dispatcher.append(" switch(fname){")

    for fname in dump_funcs.keys():
        dispatcher.append('    case "{}":'.format(fname))
        dispatcher.append("      if (ret == null){ var is_onenter = 1; } else { var is_onenter = 0; };")

        # there is no ret for onEnter dumps
        dispatcher.append("      if(is_onenter == 0){")
        dispatcher.append("        dump_{}_ret(ret, args, is_onenter);".format(fname))
        dispatcher.append("        if(ret.toInt32() < 0){ break; }")
        dispatcher.append("      }")

        for arg_idx, arg in enumerate(dump_funcs[fname]):
            argname = arg['spelling']
            if argname == "ret":
                continue

            # TODO: traversing dev is hard and we don't really need it for now.
            if argname == "dev":
                # still need the push to saved_args though
                dispatcher.append("      if(is_onenter) {{ saved_args.push(args[{}]); }}".format(arg_idx+1))
                continue

            dispatcher.append("      if(is_onenter) {{ saved_args.push(args[{}]); }}".format(arg_idx+1))

            if arg['type'].kind == TypeKind.POINTER and not arg['type'].get_pointee().is_const_qualified():
                # param is ptr but not const qualified, therefore we treat it as an output param and only dump it onLeave
                dispatcher.append("      if(is_onenter == 0){")
                dispatcher.append("         dump_{}_{}(args[{}], args, is_onenter);".format(fname, argname, arg_idx+1))
                dispatcher.append("      }")
            else:
                # param is ptr and const qualified, therefore we treat it as an input param and dump it onEnter *and* onLeave
                dispatcher.append("      dump_{}_{}(args[{}], args, is_onenter);".format(fname, argname, arg_idx+1))

        dispatcher.append("      break;\n")

    dispatcher.append("  }") # Close switch
    dispatcher.append("}") # Close function dump(...)

    out = "\n".join(dispatcher) + "\n" + "\n".join(jscode)
    return out


def collect_fptr_and_args(fptr, arg_list):
    """ should return all info we need to generate protobuf elem for this fptr """
    # iterate over function pointer params
    for idx, fptr_param in enumerate(fptr.get_arguments()):
        # it seems that clang does not provide the return value for get_children() for primitive types
        if fptr_param.kind == CursorKind.PARM_DECL:
            log.debug("{} ({})".format(fptr_param.spelling, fptr_param.type.spelling))
            arg_list.append({'spelling': fptr_param.spelling, 'type': fptr_param.type})
        elif idx == 0 and fptr_param.kind == CursorKind.TYPE_REF:
            # this is the return type case, we handle return types consistently below
            continue
        else:
            log.error("What is this?")
            import ipdb; ipdb.set_trace()

    # get return type
    fproto = fptr.type
    if fproto.kind != TypeKind.FUNCTIONPROTO:
        log.error("What is this?")
        import ipdb; ipdb.set_trace()
    arg_list.append({'spelling': 'ret', 'type': fproto.get_result()})


def collect_fptrs(definition, fptrs):
    # iterate over definition's members
    for node in definition.get_children():

        # we only consider function pointer members
        if node.type.kind == TypeKind.FUNCTIONPROTO and \
                node.kind == CursorKind.CXX_METHOD and \
                node.spelling == "generateKey":  # TODO: remove this condition later
            #log.debug("##### {} ({}) of type {} ({}) of def {}".format(node.spelling, node.kind, node.type.spelling, node.type.kind, node.type.get_declaration()))
            #if node.spelling not in ["generate_key", "get_key_characteristics"]:
            #    continue
            fptrs[node.spelling] = []
            collect_fptr_and_args(node, fptrs[node.spelling])


def get_definition(node, def_spelling):
    """ Recurse TU until we find the node we are looking for. """

    #log.debug("{} ({}) of type {} ({})".format(node.spelling, node.kind, node.type.spelling, node.type.kind))
    if node.kind == CursorKind.STRUCT_DECL and node.type.kind == TypeKind.RECORD and def_spelling == node.spelling:
        log.debug("got it!")
        return node.type.get_declaration().get_definition()
    for c in node.get_children():
        ret = get_definition(c, def_spelling)
        if ret:
            return ret
    return None


def main(struct_def, header_file, clang_options):
    global type_info

    index = Index.create()
    tu = index.parse(header_file, clang_options)
    log.info('Translation unit: {}'.format(tu.spelling))
    log.info('Args: {}'.format(clang_options))

    # this is only to check if we encountered errors during parsing
    diagnostics = [d for d in tu.diagnostics]
    if len(diagnostics) > 0:
        should_terminate = False
        for d in diagnostics:
            log.warn(d)
            if d.severity >= Diagnostic.Error:
                should_terminate = True

        if should_terminate:
            print("Error parsing translation unit.")
            sys.exit()

    # traverse the translation unit looking for the definition we are interested in
    definition = get_definition(tu.cursor, struct_def)
    log.info("{} ({}) of type {} ({})".format(definition.spelling, definition.kind, definition.type.spelling, definition.type.kind))

    # collect all methods of the struct given by `definition` and store their information in type_info['fptr']
    collect_fptrs(definition, type_info['fptr'])

    # iterate over all fptrs stored in type_info['fptr'] and generate js code for FRIDA to dump each parameter
    code = process_fptrs(definition, type_info['fptr'])

    # TODO: uncomment when code generation works
    # print(jsbeautifier.beautify(code))


def usage():
    print("{} <struct_name> <header_file> [<clang_options>]".format(sys.argv[0]))
    print("\nE.g.:")
    print("\t{} \"struct keymaster1_device\" km.hpp".format(sys.argv[0]))
    print("\t{} \"struct gatekeeper_device\" gk.hpp".format(sys.argv[0]))
    print("\t{} \"struct fingerprint_device\" fp.hpp".format(sys.argv[0]))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()
        sys.exit(0)

    main(sys.argv[1], sys.argv[2], sys.argv[3:])
