from clang.cindex import Cursor, CursorKind, TypeKind, Type

################################################################################
# TYPING
################################################################################

from typing import Tuple, List, Optional, Set, Dict

################################################################################
# CODE
################################################################################

def js_globals() -> str:
    return f"""
    var fptr_callback_cb = null;
    """

def record_param(func_name: str, param_name: str, body: str):
    return f"""
function record_{func_name}_{param_name}(arg, args, is_onenter, dump_id) {{
    {body}
}}
"""


def marshal_scalar():
    return f"""
function marshal_scalar(arg, sz) {{
    var ret = arg;
    if (!(arg instanceof ArrayBuffer)) {{
        console.log("type: " + (typeof arg));
        ret = intToArray(arg, sz);
    }} else {{
        ret = arg.slice(0, sz);
    }}
    return ret;
}}
"""


def call_marshal_scalar(src: str, dst: str, sz: int):
    assert sz in [1, 2, 4, 8], "wrong size for scalar"
    return f"""
{dst} = marshal_scalar({src}, {sz});
"""


################################################################################
# ARG CTX CODE
################################################################################


def open_arg_ctx():
    return f"""
function open_arg_ctx(func_name, param_name, param_type, is_onenter, dump_id) {{

    var ret;

    ret = {{
        'lvl': 'high',
        'type': 'open_arg_ctx',
        'func_name': func_name,
        'param_name': param_name,
        'param_type': param_type,
        'on_enter': is_onenter,
        'dump_id': dump_id
    }}

    send(ret);

}}
"""


def call_open_arg_ctx(func_name: str, param_name: str, type_name: str):
    return f"""
open_arg_ctx("{func_name}", "{param_name}", "{type_name}", is_onenter, dump_id);
"""


def close_arg_ctx():
    return f"""
function close_arg_ctx(func_name, param_name, param_type, is_onenter, dump_id) {{

    var ret;

    ret = {{
        'lvl': 'high',
        'type': 'close_arg_ctx',
        'func_name': func_name,
        'param_name': param_name,
        'param_type': param_type,
        'on_enter': is_onenter,
        'dump_id': dump_id
    }}

    send(ret);

}}
"""


def call_close_arg_ctx(func_name: str, param_name: str, type_name: str):
    return f"""
close_arg_ctx("{func_name}", "{param_name}", "{type_name}", is_onenter, dump_id);
"""


################################################################################
# RECORD CTX CODE
################################################################################


def open_record_ctx():
    return f"""
function open_record_ctx(param_name, record_type, parent, is_onenter, dump_id) {{

    var ret;

    ret = {{
        'lvl': 'high',
        'type': 'open_record_ctx',
        'param_name': param_name,
        'record_type': record_type,
        'parent': parent,
        'on_enter': is_onenter,
        'dump_id': dump_id
    }}

    send(ret);

}}
"""


def call_open_record_ctx(param_name: str, record_type: str, parent: str):
    return f"""
open_record_ctx("{param_name}", "{record_type}", "{parent}", is_onenter, dump_id);
"""


def close_record_ctx():
    return f"""
function close_record_ctx(param_name, record_type, is_onenter, dump_id) {{

    var ret;

    ret = {{
        'lvl': 'high',
        'type': 'close_record_ctx',
        'param_name': param_name,
        'record_type': record_type,
        'on_enter': is_onenter,
        'dump_id': dump_id
    }}

    send(ret);

}}
"""


def call_close_record_ctx(param_name: str, record_type: str):
    return f"""
close_record_ctx("{param_name}", "{record_type}", is_onenter, dump_id);
"""


################################################################################
# ARRAY CTX CODE
################################################################################


def open_array_ctx():
    return f"""
function open_array_ctx(param_name, array_type, parent, is_onenter, dump_id) {{

    var ret;

    ret = {{
        'lvl': 'high',
        'type': 'open_array_ctx',
        'param_name': param_name,
        'array_type': array_type,
        'parent': parent,
        'on_enter': is_onenter,
        'dump_id': dump_id
    }}

    send(ret);

}}
"""


def call_open_array_ctx(param_name: str, array_type: str, parent: str):
    return f"""
open_array_ctx("{param_name}", "{array_type}", "{parent}", is_onenter, dump_id);
"""


def close_array_ctx():
    return f"""
function close_array_ctx(param_name, array_type, is_onenter, dump_id) {{

    var ret;

    ret = {{
        'lvl': 'high',
        'type': 'close_array_ctx',
        'param_name': param_name,
        'array_type': array_type,
        'on_enter': is_onenter,
        'dump_id': dump_id
    }}

    send(ret);

}}
"""


def call_close_array_ctx(param_name: str, array_type: str):
    return f"""
close_array_ctx("{param_name}", "{array_type}", is_onenter, dump_id);
"""

################################################################################
# ATTACH/DETACH FUNCTION POINTER
################################################################################

def intercept_function_pointer(fptr_name: str, arg_name: str):
    return f"""

    var v1 = Memory.readPointer(v0.add(32));
    var v2 = Memory.readPointer(v1).add(48);
    var v3 = Memory.readPointer(v2);

    // var v3 = Memory.readPointer(v0);

    if (is_onenter) {{
      fptr_{fptr_name}_{arg_name} = Interceptor.attach(v3, {{
        onEnter: function(args) {{
          console.log("onEnter: {fptr_name}()");

          // for debugging
          console.log("{fptr_name} called from:\\n" +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\\n") + "\\n");

          console.log("args[0]: " + args[0]);
          // we assign a fresh DUMP_ID to callbacks because it has not been increaded by the caller's onLeave yet
          DUMP_ID += 1;
          this.dump_id = DUMP_ID;
          this.args = new Array();

            send({{
                'lvl': 'high',
                'type': 'open_func_ctx',
                'func': '{fptr_name}',
                'dump_id': this.dump_id
            }});

          dump("{fptr_name}", args, this.args, null, this.dump_id);
        }},
        onLeave: function(ret) {{
          console.log("onLeave: {fptr_name} ()");

          send({{
                'lvl': 'high',
                'type': 'close_func_ctx',
                'func': '{fptr_name}',
                'dump_id': this.dump_id
          }});
        }}
      }});
    }} else {{
      fptr_{fptr_name}_{arg_name}.detach();
    }}
    """


################################################################################
# MISC CODE SNIPPETS
################################################################################

def hexdump(var_name: str, length: int):
    return f"""
    console.log(hexdump({var_name}, {{
      offset: 0,
      length: {length},
      header: true,
      ansi: true
    }}));
    """

def marshal_param():
    return f"""
function marshal_param(arg, func_name, param_name, leaf_name, param_type, is_onenter, dump_id) {{

    var ret;

    ret = {{
        'lvl': 'high',
        'type': 'dump',
        'on_enter': is_onenter,
        'func_name': func_name,
        'param_name': param_name,
        'leaf_name': leaf_name,
        'param_type': param_type,
        'dump_id': dump_id
    }}

    send(ret, arg);

}}
"""


def call_marshal_param(
    func_name: str, param_name: str, leaf_name: str, type_name: str
):
    return f"""
marshal_param(v0, "{func_name}", "{param_name}", "{leaf_name}", "{type_name}", is_onenter, dump_id);
"""


def deref_pointer():
    return f"""
function deref_pointer(pointer, sz) {{

    var ret;

    if (pointer instanceof NativePointer) {{
       // pass
    }} else if (pointer instanceof ArrayBuffer) {{
      pointer = arrayToInt(pointer);
      pointer = new NativePointer(pointer);
    }} else {{
      throw new Error("`pointer` is not an `ArrayBuffer`");
    }}

    var range_obj = Process.findRangeByAddress(pointer);

    if (range_obj) {{
        try {{
            ret = Memory.readByteArray(pointer, sz);
        }} catch (e) {{ 
            console.log(pointer + ' access resulted in an exception'); 
            ret = null;
        }}
    }} else {{
        console.log("Could not find rangeObj for pointer " + pointer);
        ret = null;
    }}

    if (ret) {{
        // console.log(hexdump(ret, {{
        //   offset: 0,
        //   length: 64,
        //   header: true,
        //   ansi: true
        // }}));
    }} else {{
        console.log("ret is " + ret);
    }}

    return ret;
}}
"""


def call_deref_pointer(src: str, dst: str, sz: str):
    return f"""
    {dst} = deref_pointer({src}, {sz});
"""


def dispatcher(body: str) -> str:

    return f"""
function dump(fname, args, saved_args, ret, dump_id){{
    switch(fname){{
        {body}
    }}
}}"""


def dispatcher_body_case(func_name: str, args: List[Cursor]) -> str:

    out = ""

    # prepare renaming of args
    rename_args = ""
    for arg_idx, arg in enumerate(args):
        if not arg:
            continue
        rename_args += f"var {arg.spelling} = args[{arg_idx}];\n"

    # prepare pushing of arguments
    push_args = ""
    for arg_idx in range(len(args)):
        push_args += f"saved_args.push(args[{arg_idx}]);\n"

    out += f"""
case "{func_name}":\n

    // rename arguments
    {rename_args}

    // use `ret` to determine if this is `onEnter` or `onLeave`
    if (ret == null){{
        var is_onenter = 1;
    }} else {{ 
        var is_onenter = 0;
    }};

    // if we are in `onLeave`, record and check the return code.
    // if the return code indicates an error, abort.
    if(is_onenter == 0){{

        record_{func_name}_ret(ret, args, is_onenter, dump_id);

        if(ret.toInt32() < 0){{
            break;
        }}
    }} else {{
        {push_args}
    }}

"""

#     if func_name.endswith("_cb"):
#         # this is a CPP HAL callback and needs special treatment
#         out += """
#     if(is_onenter) {
#         var err = arrayToInt(Memory.readByteArray(args[1], 4));
#         if(err != 0){
#             break;
#         }
#     }
# """
    return out


def dispatcher_body_case_arg(func_name: str, arg: Cursor) -> str:

    out = ""
    if (arg.type.kind == TypeKind.POINTER):
        out += f"""
        if ({arg.spelling} == 0) {{
            console.log("{arg.spelling} ({arg.type.spelling}) is 0x0");
            break;
        }}
        """

    if (
        arg.type.kind == TypeKind.POINTER
        and not arg.type.get_pointee().is_const_qualified()
    ):
        # param is ptr but not const qualified, therefore we treat it as an
        # output param and only dump it onLeave
        out += f"""
            if(is_onenter == 0){{
                // Treating `{arg.type.spelling}` as input/output param
                record_{func_name}_{arg.spelling}({arg.spelling}, args, is_onenter, dump_id);
            }}
"""
    else:
        # param is ptr and const qualified or scalar, therefore we treat it
        # as an input param and dump it onEnter *and* onLeave
        out += f"""
        record_{func_name}_{arg.spelling}({arg.spelling}, args, is_onenter, dump_id);
"""
    return out
