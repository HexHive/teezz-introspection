/* Hooking and recording logic for the TEE driver as found on Huawei devices. */

var TC_MAGIC = 0x74;
var PTR_SZ = 8;

// dirty hack to prevent collisions with high-lvl dump ids
// TODO: we should fix this in `dualrecorder`
var DUMP_ID = 1 << 16;
var DEBUG = true;

var ioctl = Module.findExportByName("libc.so", "ioctl");
var mmap = Module.findExportByName("libc.so", "mmap");
var property_get = Module.findExportByName(null, '__system_property_get');


// sizeof(TC_NS_ClientContext): 0x90 if EMUI < 8 else 0x98
var emui_version = null;
if (property_get) {
    const SYSTEM_PROPERTY_GET_F = new NativeFunction(property_get, 'void', ['pointer', 'pointer']);
    var mem = Memory.alloc(128);
    SYSTEM_PROPERTY_GET_F(Memory.allocUtf8String("ro.build.version.emui"), mem);
    var emui_version = mem.readUtf8String();
} else {
    console.log("Could not find `__system_property_get`.")
}

if (emui_version == "EmotionUI_4.1.1") {
    var SIZE_TC_NS_ClientContext = 0x90;
} else {
    // TODO: add more version checking/selection if this causes problems
    var SIZE_TC_NS_ClientContext = 0x98;
}

console.log("Using SIZE_TC_NS_ClientContext of size 0x" + SIZE_TC_NS_ClientContext.toString(16));
var SIZE_load_app_ioctl_struct = 0x1c;
var SIZE_TC_NS_Time = 0x8;
/*
 * These constants are the commands given to the ioctl-command handler.
 * E.g., request in `int ioctl(int fd, unsigned long request, ...);`.
 * The commands are dependent on the size of the data type passed to the kernel.
 * If this data type changes, the command changes too.
 * This is why we need to spcify the sizes first.
 */
var TC_NS_CLIENT_IOCTL_SES_OPEN_REQ = ((0x40 << 24) | (SIZE_TC_NS_ClientContext << 16) | (TC_MAGIC << 8) | 1) >>> 0;
var TC_NS_CLIENT_IOCTL_SES_CLOSE_REQ = ((0xc0 << 24) | (SIZE_TC_NS_ClientContext << 16) | (TC_MAGIC << 8) | 2) >>> 0;
var TC_NS_CLIENT_IOCTL_SEND_CMD_REQ = ((0xc0 << 24) | (SIZE_TC_NS_ClientContext << 16) | (TC_MAGIC << 8) | 3) >>> 0;
var TC_NS_CLIENT_IOCTL_SHRD_MEM_RELEASE = ((0xc0 << 24) | (0x04 << 16) | (TC_MAGIC << 8) | 4) >>> 0;
var TC_NS_CLIENT_IOCTL_WAIT_EVENT = ((0xc0 << 24) | (0x04 << 16) | (TC_MAGIC << 8) | 5) >>> 0;
var TC_NS_CLIENT_IOCTL_SEND_EVENT_REPONSE = ((0xc0 << 24) | (0x04 << 16) | (TC_MAGIC << 8) | 6) >>> 0;
var TC_NS_CLIENT_IOCTL_REGISTER_AGENT = ((0xc0 << 24) | (0x04 << 16) | (TC_MAGIC << 8) | 7) >>> 0;
var TC_NS_CLIENT_IOCTL_UNREGISTER_AGENT = ((0xc0 << 24) | (0x04 << 16) | (TC_MAGIC << 8) | 8) >>> 0;
var TC_NS_CLIENT_IOCTL_LOAD_APP_REQ = ((0xc0 << 24) | (SIZE_load_app_ioctl_struct << 16) | (TC_MAGIC << 8) | 9) >>> 0;
var TC_NS_CLIENT_IOCTL_NEED_LOAD_APP = ((0xc0 << 24) | (SIZE_TC_NS_ClientContext << 16) | (TC_MAGIC << 8) | 10) >>> 0;
var TC_NS_CLIENT_IOCTL_LOAD_APP_EXCEPT = ((0xc0 << 24) | (TC_MAGIC << 8) | 11) >>> 0;  // deprecated
var TC_NS_CLIENT_IOCTL_ALLOC_EXCEPTING_MEM = ((0xc0 << 24) | (0x04 << 16) | (TC_MAGIC << 8) | 12) >>> 0;
var TC_NS_CLIENT_IOCTL_CANCEL_CMD_REQ = ((0xc0 << 24) | (SIZE_TC_NS_ClientContext << 16) | (TC_MAGIC << 8) | 13) >>> 0;
var TC_NS_CLIENT_IOCTL_LOGIN = ((0xc0 << 24) | (0x04 << 16) | (TC_MAGIC << 8) | 14) >>> 0;
var TC_NS_CLIENT_IOCTL_TST_CMD_REQ = ((0xc0 << 24) | (0x04 << 16) | (TC_MAGIC << 8) | 15) >>> 0;
var TC_NS_CLIENT_IOCTL_TUI_EVENT = ((0xc0 << 24) | (0x04 << 16) | (TC_MAGIC << 8) | 16) >>> 0;
var TC_NS_CLIENT_IOCTL_SYC_SYS_TIME = ((0xc0 << 24) | (SIZE_TC_NS_Time << 16) | (TC_MAGIC << 8) | 17) >>> 0;
var TC_NS_CLIENT_IOCTL_SET_NATIVE_IDENTITY = ((0xc0 << 24) | (0x04 << 16) | (TC_MAGIC << 8) | 18) >>> 0;
var TC_NS_CLIENT_IOCTL_LOAD_TTF_FILE = ((0xc0 << 24) | (0x04 << 16) | (TC_MAGIC << 8) | 19) >>> 0;

var cmd2label = {};
cmd2label[TC_NS_CLIENT_IOCTL_SES_OPEN_REQ] = "TC_NS_CLIENT_IOCTL_SES_OPEN_REQ";
cmd2label[TC_NS_CLIENT_IOCTL_SES_CLOSE_REQ] = "TC_NS_CLIENT_IOCTL_SES_CLOSE_REQ";
cmd2label[TC_NS_CLIENT_IOCTL_SEND_CMD_REQ] = "TC_NS_CLIENT_IOCTL_SEND_CMD_REQ";
cmd2label[TC_NS_CLIENT_IOCTL_SHRD_MEM_RELEASE] = "TC_NS_CLIENT_IOCTL_SHRD_MEM_RELEASE";
cmd2label[TC_NS_CLIENT_IOCTL_WAIT_EVENT] = "TC_NS_CLIENT_IOCTL_WAIT_EVENT";
cmd2label[TC_NS_CLIENT_IOCTL_SEND_EVENT_REPONSE] = "TC_NS_CLIENT_IOCTL_SEND_EVENT_REPONSE";
cmd2label[TC_NS_CLIENT_IOCTL_REGISTER_AGENT] = "TC_NS_CLIENT_IOCTL_REGISTER_AGENT";
cmd2label[TC_NS_CLIENT_IOCTL_UNREGISTER_AGENT] = "TC_NS_CLIENT_IOCTL_UNREGISTER_AGENT";
cmd2label[TC_NS_CLIENT_IOCTL_LOAD_APP_REQ] = "TC_NS_CLIENT_IOCTL_LOAD_APP_REQ";
cmd2label[TC_NS_CLIENT_IOCTL_NEED_LOAD_APP] = "TC_NS_CLIENT_IOCTL_NEED_LOAD_APP";
cmd2label[TC_NS_CLIENT_IOCTL_LOAD_APP_EXCEPT] = "TC_NS_CLIENT_IOCTL_LOAD_APP_EXCEPT";
cmd2label[TC_NS_CLIENT_IOCTL_ALLOC_EXCEPTING_MEM] = "TC_NS_CLIENT_IOCTL_ALLOC_EXCEPTING_MEM";
cmd2label[TC_NS_CLIENT_IOCTL_CANCEL_CMD_REQ] = "TC_NS_CLIENT_IOCTL_CANCEL_CMD_REQ";
cmd2label[TC_NS_CLIENT_IOCTL_LOGIN] = "TC_NS_CLIENT_IOCTL_LOGIN";
cmd2label[TC_NS_CLIENT_IOCTL_TST_CMD_REQ] = "TC_NS_CLIENT_IOCTL_TST_CMD_REQ";
cmd2label[TC_NS_CLIENT_IOCTL_TUI_EVENT] = "TC_NS_CLIENT_IOCTL_TUI_EVENT";
cmd2label[TC_NS_CLIENT_IOCTL_SYC_SYS_TIME] = "TC_NS_CLIENT_IOCTL_SYC_SYS_TIME";
cmd2label[TC_NS_CLIENT_IOCTL_SET_NATIVE_IDENTITY] = "TC_NS_CLIENT_IOCTL_SET_NATIVE_IDENTITY";
cmd2label[TC_NS_CLIENT_IOCTL_LOAD_TTF_FILE] = "TC_NS_CLIENT_IOCTL_LOAD_TTF_FILE";


// param types
var TEEC_NONE = 0x0;
var TEEC_VALUE_INPUT = 0x01;
var TEEC_VALUE_OUTPUT = 0x02;
var TEEC_VALUE_INOUT = 0x03;
var TEEC_MEMREF_TEMP_INPUT = 0x05;
var TEEC_MEMREF_TEMP_OUTPUT = 0x06;
var TEEC_MEMREF_TEMP_INOUT = 0x07;
var TEEC_MEMREF_WHOLE = 0xc;
var TEEC_MEMREF_PARTIAL_INPUT = 0xd;
var TEEC_MEMREF_PARTIAL_OUTPUT = 0xe;
var TEEC_MEMREF_PARTIAL_INOUT = 0xf;

var type2label = {};
type2label[TEEC_NONE] = "TEEC_NONE";
type2label[TEEC_VALUE_INPUT] = "TEEC_VALUE_INPUT";
type2label[TEEC_VALUE_OUTPUT] = "TEEC_VALUE_OUTPUT";
type2label[TEEC_VALUE_INOUT] = "TEEC_VALUE_INOUT";
type2label[TEEC_MEMREF_TEMP_INPUT] = "TEEC_MEMREF_TEMP_INPUT";
type2label[TEEC_MEMREF_TEMP_OUTPUT] = "TEEC_MEMREF_TEMP_OUTPUT";
type2label[TEEC_MEMREF_TEMP_INOUT] = "TEEC_MEMREF_TEMP_INOUT";
type2label[TEEC_MEMREF_WHOLE] = "TEEC_MEMREF_WHOLE";
type2label[TEEC_MEMREF_PARTIAL_INPUT] = "TEEC_MEMREF_PARTIAL_INPUT";
type2label[TEEC_MEMREF_PARTIAL_OUTPUT] = "TEEC_MEMREF_PARTIAL_OUTPUT";
type2label[TEEC_MEMREF_PARTIAL_INOUT] = "TEEC_MEMREF_PARTIAL_INOUT";


function get_struct_size(cmd) {
    return (cmd & 0x00ff0000) >> 16;
}

function is_tc(cmd) {
    if (get_magic(cmd) == TC_MAGIC)
        return true;
    else
        return false;
}

function get_magic(cmd) {
    return (cmd & 0x0000ff00) >> 8;
}

function get_param_type(param_types, idx) {
    return (param_types >>> (idx * 4) & 0x0f)
}

function dump_tc_client_context(ctx, size, is_on_enter) {
    /*
    typedef struct {
        unsigned char uuid[16];
        __u32 session_id;
        __u32 cmd_id;
        TC_NS_ClientReturn returns;
        TC_NS_ClientLogin login;
        TC_NS_ClientParam params[4];
        __u32 paramTypes;
        __u8 started;
    } TC_NS_ClientContext;
    */

    var hd = hexdump(ctx, { length: size, header: true, ansi: true });
    //console.log(hd);

    var curr_ptr = ctx
    var uuid = Memory.readByteArray(curr_ptr, 16)
    var curr_ptr = ctx.add(16)
    var session_id = Memory.readByteArray(curr_ptr, 4)
    var curr_ptr = ctx.add(20)
    var cmd_id = Memory.readByteArray(curr_ptr, 4)

    // TC_NS_ClientReturn
    var curr_ptr = ctx.add(24)
    if (is_on_enter) {
        //Memory.writeByteArray(curr_ptr, [0x61, 0x61, 0x61, 0x61])
    }
    var return_code = Memory.readByteArray(curr_ptr, 4)
    var curr_ptr = ctx.add(28)
    if (is_on_enter) {
        //Memory.writeByteArray(curr_ptr, [0x62, 0x62, 0x62, 0x62])
    }
    var return_origin = Memory.readByteArray(curr_ptr, 4)

    // TC_NS_ClientLogin
    var curr_ptr = ctx.add(32)
    var login_method = Memory.readByteArray(curr_ptr, 4)
    var curr_ptr = ctx.add(36)
    var login_mdata = Memory.readByteArray(curr_ptr, 4)

    // TC_NS_ClientParam
    var params = {}
    for (var i = 0; i < 4; i++) {
        params[i] = {}
        var curr_ptr = ctx.add(40 + i * (3 * PTR_SZ))
        params[i]["param_a"] = Memory.readU64(curr_ptr)
        var curr_ptr = ctx.add(40 + i * (3 * PTR_SZ) + PTR_SZ)
        params[i]["param_b"] = Memory.readU64(curr_ptr)
        params[i]["param_b_bytes"] = Memory.readByteArray(curr_ptr, PTR_SZ)
        var curr_ptr = ctx.add(40 + i * (3 * PTR_SZ) + 2 * PTR_SZ)
        params[i]["param_c"] = Memory.readU64(curr_ptr)
    }

    // paramTypes and started
    var curr_ptr = ctx.add(40 + 4 * (3 * PTR_SZ))
    var param_types = Memory.readU32(curr_ptr)
    var curr_ptr = ctx.add(40 + 4 * (3 * PTR_SZ) + 4)
    var started = Memory.readByteArray(curr_ptr, 1)


    for (var i = 0; i < 4; i++) {
        var param_type = get_param_type(param_types, i);

        switch (param_type) {
            case TEEC_NONE:
                //console.log("NONE")
                break;
            case TEEC_VALUE_INPUT:
            case TEEC_VALUE_OUTPUT:
            case TEEC_VALUE_INOUT:
                //console.log("VAL")
                if (params[i]["param_a"] != 0) {
                    params[i]["param_a_data"] = Memory.readByteArray(ptr(params[i]["param_a"]), PTR_SZ);
                } else {
                    params[i]["param_a_data"] = null;
                }
                if (params[i]["param_b"] != 0) {
                    params[i]["param_b_data"] = Memory.readByteArray(ptr(params[i]["param_b"]), PTR_SZ);
                } else {
                    params[i]["param_b_data"] = null;
                }
                if (params[i]["param_c"] != 0) {
                    params[i]["param_c_data"] = Memory.readByteArray(ptr(params[i]["param_c"]), PTR_SZ);
                } else {
                    params[i]["param_c_data"] = null;
                }

                break;
            case TEEC_MEMREF_TEMP_INPUT:
            case TEEC_MEMREF_TEMP_OUTPUT:
            case TEEC_MEMREF_TEMP_INOUT:
            case TEEC_MEMREF_WHOLE:
            case TEEC_MEMREF_PARTIAL_INPUT:
            case TEEC_MEMREF_PARTIAL_OUTPUT:
            case TEEC_MEMREF_PARTIAL_INOUT:
                //console.log("MEMREF dump_id " + DUMP_ID + " param no " + i + " memref " + type2label[param_type]);


                if (0 != params[i]["param_c"].and(uint64(0xffff000000000000)).compare(uint64(0))) {
                    console.log("kernel address! (" + params[i]["param_c"].toString(16) + ")")
                    break;
                }

                // get size
                var buf_sz = null
                if (params[i]["param_c"] != 0) {
                    buf_sz = Memory.readU64(ptr(params[i]["param_c"]));
                    params[i]["param_c_data"] = Memory.readByteArray(ptr(params[i]["param_c"]), PTR_SZ);
                } else {
                    console.log("size for memref missing.")
                    break;
                }

                // get offset
                if (params[i]["param_b"] != 0) {
                    // this is not a ptr to offset, it is directly the offset!
                    //params[i]["param_b_data"] = Memory.readU64(ptr(params[i]["param_b"]));
                    params[i]["param_b_data"] = params[i]["param_b_bytes"];
                } else {
                    //console.log("offset for memref missing.")
                    params[i]["param_b_data"] = null;
                }

                // get buffer
                if (params[i]["param_a"] != 0) {
                    params[i]["param_a_data"] = Memory.readByteArray(ptr(params[i]["param_a"]), buf_sz);
                } else {
                    console.log("ptr to memref buffer missing.")
                }

                break;
            default:
                console.log("WTF?")
                break;
        }
    }

    //console.log(uuid);
    //console.log(session_id);
    //console.log(cmd_id);
    //console.log("STATUS:");
    //console.log(return_code)
    //console.log("CODE:");
    //console.log(return_origin)
    //console.log(login_method);
    //console.log(login_mdata);
    //console.log(param_types.toString(16));
    //console.log(started);

    for (var i = 0; i < 4; i++) {
        //console.log("param_" + i + "_a: " + params[i]["param_a"].toString(16));
        //console.log("param_" + i + "_b: " + params[i]["param_b"].toString(16));
        //console.log("param_" + i + "_c: " + params[i]["param_c"].toString(16));
        //console.log(params[i]["param_a_data"]);
        //console.log(params[i]["param_b_data"]);
        //console.log(params[i]["param_c_data"]);
    }

    var ctx_data = Memory.readByteArray(ctx, size);
    send({ "type": "TC_NS_ClientContext", "on_enter": is_on_enter, "dump_id": DUMP_ID }, ctx_data)
    for (var i = 0; i < 4; i++) {
        send({ "type": "param_" + i + "_a", "on_enter": is_on_enter, "dump_id": DUMP_ID }, params[i]["param_a_data"])
        send({ "type": "param_" + i + "_b", "on_enter": is_on_enter, "dump_id": DUMP_ID }, params[i]["param_b_data"])
        send({ "type": "param_" + i + "_c", "on_enter": is_on_enter, "dump_id": DUMP_ID }, params[i]["param_c_data"])
    }
    //console.log("DONE!")
}

Interceptor.attach(ioctl, {
    onEnter: function (args) {

        this.request = parseInt(args[1], 16);
        if (is_tc(this.request)) {
            console.log("### onEnter start ###");
        }

        if (DEBUG) {
            if (is_tc(this.request)) {
                // print the ioctl request label
                if (cmd2label[this.request] == undefined) {
                    console.log(this.request);
                }
                else
                    console.log(cmd2label[this.request]);
            }
        }

        if (this.request == TC_NS_CLIENT_IOCTL_SES_OPEN_REQ) {
            /*
            this.ctx = ptr(args[2])
            this.size = get_struct_size(this.request);
            send({"type": "struct",
                  "name": "TC_NS_ClientContext",
                  "cmd": cmd2label[TC_NS_CLIENT_IOCTL_SES_OPEN_REQ],
                  "dump_id": DUMP_ID })
            dump_tc_client_context(this.ctx, this.size, true);
            */
        } else if (this.request == TC_NS_CLIENT_IOCTL_SES_CLOSE_REQ) {
            /*
            this.ctx = ptr(args[2])
            this.size = get_struct_size(this.request);
            send({"type": "struct",
                  "name": "TC_NS_ClientContext",
                  "cmd": cmd2label[TC_NS_CLIENT_IOCTL_SES_CLOSE_REQ],
                  "dump_id": DUMP_ID })
            dump_tc_client_context(this.ctx, this.size, true);
            */
        } else if (this.request == TC_NS_CLIENT_IOCTL_LOAD_APP_REQ) {
            this.ctx = ptr(args[2])
            this.size = get_struct_size(this.request);
            send({
                "type": "struct",
                "name": "TC_NS_ClientContext",
                "cmd": cmd2label[TC_NS_CLIENT_IOCTL_LOAD_APP_REQ],
                "dump_id": DUMP_ID
            })
            dump_tc_client_context(this.ctx, this.size, true);
        } else if (this.request == TC_NS_CLIENT_IOCTL_SEND_CMD_REQ) {
            console.log("ioctl called from:\n" +
                Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join("\n") + "\n");

            this.ctx = ptr(args[2])
            this.size = get_struct_size(this.request);
            send({
                "type": "struct",
                "name": "TC_NS_ClientContext",
                "cmd": cmd2label[TC_NS_CLIENT_IOCTL_SEND_CMD_REQ],
                "dump_id": DUMP_ID
            })
            dump_tc_client_context(this.ctx, this.size, true);
        } else {
            console.log("Not handling cmd " + this.request.toString(16))
        }

        if (is_tc(this.request)) {
            console.log("### onEnter end ###");
        }
    },
    onLeave: function (retval) {

        if (is_tc(this.request)) {
            //console.log("### onLeave start ###");
        }

        if (this.request == TC_NS_CLIENT_IOCTL_SES_OPEN_REQ) {
            /*
            dump_tc_client_context(this.ctx, this.size, false);
            DUMP_ID += 1;
            */
        } else if (this.request == TC_NS_CLIENT_IOCTL_SES_CLOSE_REQ) {
            /*
            dump_tc_client_context(this.ctx, this.size, false);
            DUMP_ID += 1;
            */
        } else if (this.request == TC_NS_CLIENT_IOCTL_SEND_CMD_REQ) {
            dump_tc_client_context(this.ctx, this.size, false);
            send({ "type": "done", "dump_id": DUMP_ID })
            DUMP_ID += 1;
        } else if (this.request == TC_NS_CLIENT_IOCTL_LOAD_APP_REQ) {
            dump_tc_client_context(this.ctx, this.size, false);
            send({ "type": "done", "dump_id": DUMP_ID })
            DUMP_ID += 1;
        } else {
            //console.log("Not handling cmd " + this.request.toString(16))
        }

        if (is_tc(this.request)) {
            //console.log("### onLeave end ###");
        }
    }
});

Interceptor.attach(mmap, {
    onEnter: function (args) {
        var addr = args[0];
        var len = args[1];
        var prot = args[2];
        var flags = args[3];
        var mmapFD = args[4];
        var offset = args[5];
        console.log('mmap(' + addr + ', ' + len + ', ' + prot + ', ' + flags + ', ' + mmapFD + ', ' + offset + ')');
    },
    onLeave: function (ret) {
        console.log('\tret: ' + ret);
    }
});

