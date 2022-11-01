var ioctl = Module.findExportByName("libc.so", "ioctl");
var mmap = Module.findExportByName("libc.so", "mmap");
var fd_to_addr = {};
var buf_onenter = null;
var buf_onleave = null;


var QC_MAGIC = 0x97
//PTR_SZ = 8
var DUMP_ID = 1 << 16;

var QSEECOM_IOCTL_REGISTER_LISTENER_REQ = (0xc0189701) >>> 0
var QSEECOM_IOCTL_UNREGISTER_LISTENER_REQ = (0x9702) >>> 0
var QSEECOM_IOCTL_SEND_CMD_REQ = (0xc0209703) >>> 0
var QSEECOM_IOCTL_SEND_MODFD_CMD_REQ = (0xc0409704) >>> 0
var QSEECOM_IOCTL_RECEIVE_REQ = (0x9705) >>> 0
var QSEECOM_IOCTL_SEND_RESP_REQ = (0x9706) >>> 0
var QSEECOM_IOCTL_LOAD_APP_REQ = (0xc0509707) >>> 0
var QSEECOM_IOCTL_SET_MEM_PARAM_REQ = (0xc0189708) >>> 0
var QSEECOM_IOCTL_UNLOAD_APP_REQ = (0x9709) >>> 0
var QSEECOM_IOCTL_GET_QSEOS_VERSION_REQ = (0xc004970a) >>> 0
var QSEECOM_IOCTL_PERF_ENABLE_REQ = (0x970b) >>> 0
var QSEECOM_IOCTL_PERF_DISABLE_REQ = (0x970c) >>> 0
var QSEECOM_IOCTL_LOAD_EXTERNAL_ELF_REQ = (0xc050970d) >>> 0
var QSEECOM_IOCTL_UNLOAD_EXTERNAL_ELF_REQ = (0x970e) >>> 0
var QSEECOM_IOCTL_APP_LOADED_QUERY_REQ = (0xc044970f) >>> 0
var QSEECOM_IOCTL_SEND_CMD_SERVICE_REQ = (0xc0289710) >>> 0
var QSEECOM_IOCTL_CREATE_KEY_REQ = (0xc0249711) >>> 0
var QSEECOM_IOCTL_WIPE_KEY_REQ = (0xc0089712) >>> 0
var QSEECOM_IOCTL_SAVE_PARTITION_HASH_REQ = (0xc0249713) >>> 0
var QSEECOM_IOCTL_IS_ES_ACTIVATED_REQ = (0xc0049714) >>> 0
var QSEECOM_IOCTL_SEND_MODFD_RESP = (0xc0309715) >>> 0
var QSEECOM_IOCTL_SET_BUS_SCALING_REQ = (0xc0049717) >>> 0
var QSEECOM_IOCTL_UPDATE_KEY_USER_INFO_REQ = (0x9718) >>> 0
var QSEECOM_QTEEC_IOCTL_OPEN_SESSION_REQ = (0xc040971e) >>> 0
var QSEECOM_QTEEC_IOCTL_CLOSE_SESSION_REQ = (0xc020971f) >>> 0
var QSEECOM_QTEEC_IOCTL_INVOKE_MODFD_CMD_REQ = (0xc0409720) >>> 0
var QSEECOM_QTEEC_IOCTL_REQUEST_CANCELLATION_REQ = (0xc0409721) >>> 0

var COMPAT_QSEECOM_IOCTL_REGISTER_LISTENER_REQ = (0xc0109701) >>> 0
var COMPAT_QSEECOM_IOCTL_UNREGISTER_LISTENER_REQ = (0x9702) >>> 0
var COMPAT_QSEECOM_IOCTL_SEND_CMD_REQ = (0xc0109703) >>> 0
var COMPAT_QSEECOM_IOCTL_SEND_MODFD_CMD_REQ = (0xc0309704) >>> 0
var COMPAT_QSEECOM_IOCTL_RECEIVE_REQ = (0x9705) >>> 0
var COMPAT_QSEECOM_IOCTL_SEND_RESP_REQ = (0x9706) >>> 0
var COMPAT_QSEECOM_IOCTL_LOAD_APP_REQ = (0xc0549707) >>> 0
var COMPAT_QSEECOM_IOCTL_SET_MEM_PARAM_REQ = (0xc00c9708) >>> 0
var COMPAT_QSEECOM_IOCTL_UNLOAD_APP_REQ = (0x9709) >>> 0
var COMPAT_QSEECOM_IOCTL_GET_QSEOS_VERSION_REQ = (0xc004970a) >>> 0
var COMPAT_QSEECOM_IOCTL_PERF_ENABLE_REQ = (0x970b) >>> 0
var COMPAT_QSEECOM_IOCTL_PERF_DISABLE_REQ = (0x970c) >>> 0
var COMPAT_QSEECOM_IOCTL_LOAD_EXTERNAL_ELF_REQ = (0xc028970d) >>> 0
var COMPAT_QSEECOM_IOCTL_UNLOAD_EXTERNAL_ELF_REQ = (0x970e) >>> 0
var COMPAT_QSEECOM_IOCTL_APP_LOADED_QUERY_REQ = (0xc048970f) >>> 0
var COMPAT_QSEECOM_IOCTL_SEND_CMD_SERVICE_REQ = (0xc0149710) >>> 0
var COMPAT_QSEECOM_IOCTL_CREATE_KEY_REQ = (0xc0249711) >>> 0
var COMPAT_QSEECOM_IOCTL_WIPE_KEY_REQ = (0xc0089712) >>> 0
var COMPAT_QSEECOM_IOCTL_SAVE_PARTITION_HASH_REQ = (0xc0249713) >>> 0
var COMPAT_QSEECOM_IOCTL_IS_ES_ACTIVATED_REQ = (0xc0049714) >>> 0
var COMPAT_QSEECOM_IOCTL_SEND_MODFD_RESP = (0xc0189715) >>> 0
var COMPAT_QSEECOM_IOCTL_SET_BUS_SCALING_REQ = (0xc0049717) >>> 0
var COMPAT_QSEECOM_IOCTL_UPDATE_KEY_USER_INFO_REQ = (0x9718) >>> 0
var COMPAT_QSEECOM_QTEEC_IOCTL_OPEN_SESSION_REQ = (0xc020971e) >>> 0
var COMPAT_QSEECOM_QTEEC_IOCTL_CLOSE_SESSION_REQ = (0xc010971f) >>> 0
var COMPAT_QSEECOM_QTEEC_IOCTL_INVOKE_MODFD_CMD_REQ = (0xc0209720) >>> 0
var COMPAT_QSEECOM_QTEEC_IOCTL_REQUEST_CANCELLATION_REQ = (0xc0209721) >>> 0

var cmd2label = {}

cmd2label[QSEECOM_IOCTL_REGISTER_LISTENER_REQ] = "QSEECOM_IOCTL_REGISTER_LISTENER_REQ"
cmd2label[QSEECOM_IOCTL_UNREGISTER_LISTENER_REQ] = "QSEECOM_IOCTL_UNREGISTER_LISTENER_REQ"
cmd2label[QSEECOM_IOCTL_SEND_CMD_REQ] = "QSEECOM_IOCTL_SEND_CMD_REQ"
cmd2label[QSEECOM_IOCTL_SEND_MODFD_CMD_REQ] = "QSEECOM_IOCTL_SEND_MODFD_CMD_REQ"
cmd2label[QSEECOM_IOCTL_RECEIVE_REQ] = "QSEECOM_IOCTL_RECEIVE_REQ"
cmd2label[QSEECOM_IOCTL_SEND_RESP_REQ] = "QSEECOM_IOCTL_SEND_RESP_REQ"
cmd2label[QSEECOM_IOCTL_LOAD_APP_REQ] = "QSEECOM_IOCTL_LOAD_APP_REQ"
cmd2label[QSEECOM_IOCTL_SET_MEM_PARAM_REQ] = "QSEECOM_IOCTL_SET_MEM_PARAM_REQ"
cmd2label[QSEECOM_IOCTL_UNLOAD_APP_REQ] = "QSEECOM_IOCTL_UNLOAD_APP_REQ"
cmd2label[QSEECOM_IOCTL_GET_QSEOS_VERSION_REQ] = "QSEECOM_IOCTL_GET_QSEOS_VERSION_REQ"
cmd2label[QSEECOM_IOCTL_PERF_ENABLE_REQ] = "QSEECOM_IOCTL_PERF_ENABLE_REQ"
cmd2label[QSEECOM_IOCTL_PERF_DISABLE_REQ] = "QSEECOM_IOCTL_PERF_DISABLE_REQ"
cmd2label[QSEECOM_IOCTL_LOAD_EXTERNAL_ELF_REQ] = "QSEECOM_IOCTL_LOAD_EXTERNAL_ELF_REQ"
cmd2label[QSEECOM_IOCTL_UNLOAD_EXTERNAL_ELF_REQ] = "QSEECOM_IOCTL_UNLOAD_EXTERNAL_ELF_REQ"
cmd2label[QSEECOM_IOCTL_APP_LOADED_QUERY_REQ] = "QSEECOM_IOCTL_APP_LOADED_QUERY_REQ"
cmd2label[QSEECOM_IOCTL_SEND_CMD_SERVICE_REQ] = "QSEECOM_IOCTL_SEND_CMD_SERVICE_REQ"
cmd2label[QSEECOM_IOCTL_CREATE_KEY_REQ] = "QSEECOM_IOCTL_CREATE_KEY_REQ"
cmd2label[QSEECOM_IOCTL_WIPE_KEY_REQ] = "QSEECOM_IOCTL_WIPE_KEY_REQ"
cmd2label[QSEECOM_IOCTL_SAVE_PARTITION_HASH_REQ] = "QSEECOM_IOCTL_SAVE_PARTITION_HASH_REQ"
cmd2label[QSEECOM_IOCTL_IS_ES_ACTIVATED_REQ] = "QSEECOM_IOCTL_IS_ES_ACTIVATED_REQ"
cmd2label[QSEECOM_IOCTL_SEND_MODFD_RESP] = "QSEECOM_IOCTL_SEND_MODFD_RESP"
cmd2label[QSEECOM_IOCTL_SET_BUS_SCALING_REQ] = "QSEECOM_IOCTL_SET_BUS_SCALING_REQ"
cmd2label[QSEECOM_IOCTL_UPDATE_KEY_USER_INFO_REQ] = "QSEECOM_IOCTL_UPDATE_KEY_USER_INFO_REQ"
cmd2label[QSEECOM_QTEEC_IOCTL_OPEN_SESSION_REQ] = "QSEECOM_QTEEC_IOCTL_OPEN_SESSION_REQ"
cmd2label[QSEECOM_QTEEC_IOCTL_CLOSE_SESSION_REQ] = "QSEECOM_QTEEC_IOCTL_CLOSE_SESSION_REQ"
cmd2label[QSEECOM_QTEEC_IOCTL_INVOKE_MODFD_CMD_REQ] = "QSEECOM_QTEEC_IOCTL_INVOKE_MODFD_CMD_REQ"
cmd2label[QSEECOM_QTEEC_IOCTL_REQUEST_CANCELLATION_REQ] = "QSEECOM_QTEEC_IOCTL_REQUEST_CANCELLATION_REQ"

cmd2label[COMPAT_QSEECOM_IOCTL_REGISTER_LISTENER_REQ] = "COMPAT_QSEECOM_IOCTL_REGISTER_LISTENER_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_UNREGISTER_LISTENER_REQ] = "COMPAT_QSEECOM_IOCTL_UNREGISTER_LISTENER_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_SEND_CMD_REQ] = "COMPAT_QSEECOM_IOCTL_SEND_CMD_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_SEND_MODFD_CMD_REQ] = "COMPAT_QSEECOM_IOCTL_SEND_MODFD_CMD_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_RECEIVE_REQ] = "COMPAT_QSEECOM_IOCTL_RECEIVE_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_SEND_RESP_REQ] = "COMPAT_QSEECOM_IOCTL_SEND_RESP_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_LOAD_APP_REQ] = "COMPAT_QSEECOM_IOCTL_LOAD_APP_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_SET_MEM_PARAM_REQ] = "COMPAT_QSEECOM_IOCTL_SET_MEM_PARAM_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_UNLOAD_APP_REQ] = "COMPAT_QSEECOM_IOCTL_UNLOAD_APP_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_GET_QSEOS_VERSION_REQ] = "COMPAT_QSEECOM_IOCTL_GET_QSEOS_VERSION_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_PERF_ENABLE_REQ] = "COMPAT_QSEECOM_IOCTL_PERF_ENABLE_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_PERF_DISABLE_REQ] = "COMPAT_QSEECOM_IOCTL_PERF_DISABLE_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_LOAD_EXTERNAL_ELF_REQ] = "COMPAT_QSEECOM_IOCTL_LOAD_EXTERNAL_ELF_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_UNLOAD_EXTERNAL_ELF_REQ] = "COMPAT_QSEECOM_IOCTL_UNLOAD_EXTERNAL_ELF_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_APP_LOADED_QUERY_REQ] = "COMPAT_QSEECOM_IOCTL_APP_LOADED_QUERY_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_SEND_CMD_SERVICE_REQ] = "COMPAT_QSEECOM_IOCTL_SEND_CMD_SERVICE_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_CREATE_KEY_REQ] = "COMPAT_QSEECOM_IOCTL_CREATE_KEY_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_WIPE_KEY_REQ] = "COMPAT_QSEECOM_IOCTL_WIPE_KEY_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_SAVE_PARTITION_HASH_REQ] = "COMPAT_QSEECOM_IOCTL_SAVE_PARTITION_HASH_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_IS_ES_ACTIVATED_REQ] = "COMPAT_QSEECOM_IOCTL_IS_ES_ACTIVATED_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_SEND_MODFD_RESP] = "COMPAT_QSEECOM_IOCTL_SEND_MODFD_RESP"
cmd2label[COMPAT_QSEECOM_IOCTL_SET_BUS_SCALING_REQ] = "COMPAT_QSEECOM_IOCTL_SET_BUS_SCALING_REQ"
cmd2label[COMPAT_QSEECOM_IOCTL_UPDATE_KEY_USER_INFO_REQ] = "COMPAT_QSEECOM_IOCTL_UPDATE_KEY_USER_INFO_REQ"
cmd2label[COMPAT_QSEECOM_QTEEC_IOCTL_OPEN_SESSION_REQ] = "COMPAT_QSEECOM_QTEEC_IOCTL_OPEN_SESSION_REQ"
cmd2label[COMPAT_QSEECOM_QTEEC_IOCTL_CLOSE_SESSION_REQ] = "COMPAT_QSEECOM_QTEEC_IOCTL_CLOSE_SESSION_REQ"
cmd2label[COMPAT_QSEECOM_QTEEC_IOCTL_INVOKE_MODFD_CMD_REQ] = "COMPAT_QSEECOM_QTEEC_IOCTL_INVOKE_MODFD_CMD_REQ"
cmd2label[COMPAT_QSEECOM_QTEEC_IOCTL_REQUEST_CANCELLATION_REQ] = "COMPAT_QSEECOM_QTEEC_IOCTL_REQUEST_CANCELLATION_REQ"

function get_struct_size(cmd) {
    return (cmd & 0x00ff0000) >> 16;
}

function is_qc(cmd) {
    if (get_magic(cmd) == QC_MAGIC)
        return true;
    else
        return false;
}

function get_magic(cmd) {
    return (cmd & 0x0000ff00) >> 8;
}

function get_buf_len(buf) {
    var len = 0;
    var bytes = new Uint8Array(buf);
    var count = 0;
    for (count = 0; count < bytes.length; count++) {
        if (bytes[count] != 0x0) {
            len = count;
        }
    }
    return len + 1;
}

function buf_is_equal(buf1, buf2) {
    if (buf1 === null || buf2 === null) {
        return false;
    }
    var bytes1 = new Uint8Array(buf1);
    var bytes2 = new Uint8Array(buf2);
    if (bytes1.length != bytes2.length) {
        return false;
    }
    for (var count = 0; count < bytes1.length; count++) {
        if (bytes1[count] != bytes2[count]) {
            return false
        }
    }
    return true;
}

function dump_compat_qseecom_send_cmd_req(qseecom_send_cmd_req, sz, is_on_enter) {
    dump_send_cmd_req(qseecom_send_cmd_req, sz, is_on_enter, 4);
}

function dump_qseecom_send_cmd_req(send_cmd_req, sz, is_on_enter) {
    dump_send_cmd_req(send_cmd_req, sz, is_on_enter, 8);
}

function dump_compat_qseecom_send_modfd_cmd_req(qseecom_send_cmd_req, sz, is_on_enter) {
    dump_send_modfd_cmd_req(qseecom_send_cmd_req, sz, is_on_enter, 4);
}

function dump_qseecom_send_modfd_cmd_req(qseecom_send_cmd_req, sz, is_on_enter) {
    dump_send_modfd_cmd_req(qseecom_send_cmd_req, sz, is_on_enter, 8);
}

function dump_send_cmd_req(qseecom_send_cmd_req, sz, is_on_enter, ptr_sz) {
    /*
    struct qseecom_send_cmd_req {
        void *cmd_req_buf;
        unsigned int cmd_req_len;
        void *resp_buf;
        unsigned int resp_len;
    };
     */

    //console.log(args[0])
    //console.log(args[1])
    //console.log(args[2])

    var curr_ptr = qseecom_send_cmd_req.add(ptr_sz * 0)
    var cmd_req_buf = Memory.readPointer(curr_ptr)

    curr_ptr = qseecom_send_cmd_req.add(ptr_sz * 1)
    var cmd_req_len = Memory.readU32(curr_ptr)

    curr_ptr = qseecom_send_cmd_req.add(ptr_sz * 2)
    var resp_buf = Memory.readPointer(curr_ptr)

    curr_ptr = qseecom_send_cmd_req.add(ptr_sz * 3)
    var resp_len = Memory.readU32(curr_ptr)

    console.log("req len " + cmd_req_len)
    console.log("resp len " + resp_len)

    var cmd_req = Memory.readByteArray(qseecom_send_cmd_req, sz)
    var req = Memory.readByteArray(cmd_req_buf, cmd_req_len)
    var resp = Memory.readByteArray(resp_buf, resp_len)

    send({ "type": "qseecom_send_cmd_req", "dump_id": DUMP_ID, "on_enter": is_on_enter }, cmd_req)
    send({ "type": "req", "dump_id": DUMP_ID, "on_enter": is_on_enter }, req)
    send({ "type": "resp", "dump_id": DUMP_ID, "on_enter": is_on_enter }, resp)
}

function dump_send_modfd_cmd_req(qseecom_send_modfd_cmd_req, sz, is_on_enter, ptr_sz) {
    /*
    #define MAX_ION_FD  4
    struct qseecom_send_modfd_cmd_req {
        void *cmd_req_buf;
        unsigned int cmd_req_len;
        void *resp_buf;
        unsigned int resp_len;
        struct qseecom_ion_fd_info ifd_data[MAX_ION_FD];
    };
    */

    var curr_ptr = qseecom_send_modfd_cmd_req.add(ptr_sz * 0)
    var cmd_req_buf = Memory.readPointer(curr_ptr)

    curr_ptr = qseecom_send_modfd_cmd_req.add(ptr_sz * 1)
    var cmd_req_len = Memory.readU32(curr_ptr)

    curr_ptr = qseecom_send_modfd_cmd_req.add(ptr_sz * 2)
    var resp_buf = Memory.readPointer(curr_ptr)

    curr_ptr = qseecom_send_modfd_cmd_req.add(ptr_sz * 3)
    var resp_len = Memory.readU32(curr_ptr)

    var cmd_req = Memory.readByteArray(qseecom_send_modfd_cmd_req, sz)
    var req = Memory.readByteArray(cmd_req_buf, cmd_req_len)
    var resp = Memory.readByteArray(resp_buf, resp_len)


    console.log("req @ " + cmd_req_buf)
    console.log("req len " + cmd_req_len)
    console.log(hexdump(cmd_req_buf, {
        offset: 0,
        length: cmd_req_len,
        header: true,
        ansi: true
    }));

    console.log("resp @ " + resp_buf)
    console.log("resp len " + resp_len)

    console.log(hexdump(resp_buf, {
        offset: 0,
        length: resp_len,
        header: true,
        ansi: true
    }));


    // TODO: ifd_data (see struct above)
    for (var i = 0; i < 4; i++) {
        curr_ptr = qseecom_send_modfd_cmd_req.add(ptr_sz * 3 + 4 + i * 8)
        var ion_fd_info_fd = Memory.readU32(curr_ptr)
        curr_ptr = qseecom_send_modfd_cmd_req.add(ptr_sz * 4 + i * 8)
        var ion_fd_info_offset = Memory.readU32(curr_ptr)
        console.log("fd: " + ion_fd_info_fd);
        console.log("offset: " + ion_fd_info_offset);
        if (ion_fd_info_fd > 0 && ion_fd_info_fd in fd_to_addr) {
            var virt_ptr = fd_to_addr[ion_fd_info_fd][0];
            var len = fd_to_addr[ion_fd_info_fd][1];
            var shared_buf = Memory.readByteArray(virt_ptr, len);
            var dump_len = get_buf_len(shared_buf);
            // dump shared buffer only if contents differ since the last event
            if (is_on_enter) {
                // buffer hasn't changed since the last onleave
                // -> no request parameters
                buf_onenter = shared_buf;
                if (buf_is_equal(buf_onleave, shared_buf)) {
                    console.log("\n\tShared buffer didn't change -> don't dump again!\n");
                    continue;
                }
                console.log("\n\tShared memory onenter (fd: 0x" + ion_fd_info_fd.toString(16) + "):");
            } else if (buf_is_equal(buf_onenter, shared_buf)) {
                console.log("\n\tShared buffer didn't change -> don't dump again!\n");
                continue;
            } else {
                console.log("\n\tShared memory onleave (fd: 0x" + ion_fd_info_fd.toString(16) + "):");
            }

            console.log(hexdump(virt_ptr, {
                offset: 0,
                length: dump_len,
                header: true,
                ansi: true
            }));
            console.log("\n");
            send({ "type": "shared", "dump_id": DUMP_ID, "on_enter": is_on_enter }, shared_buf)
            /*if(!is_on_enter){
                //write_ptr = write_ptr.add(4 * 6);
                //write_ptr.writeU32(0x0);
                for(var c = 0; c < 3; c++){
                    var write_ptr = virt_ptr.add(c * 4);
                    write_ptr.writeU32(0x0);
                }
            }*/
        }
    }

    console.log("resp len " + resp_len)

    send({ "type": "qseecom_send_modfd_cmd_req", "dump_id": DUMP_ID, "on_enter": is_on_enter }, cmd_req)
    send({ "type": "req", "dump_id": DUMP_ID, "on_enter": is_on_enter }, req)
    send({ "type": "resp", "dump_id": DUMP_ID, "on_enter": is_on_enter }, resp)
}

var DEBUG = true;
Interceptor.attach(ioctl, {
    onEnter: function (args) {

        this.request = parseInt(args[1], 16);

        if (DEBUG) {
            if (is_qc(this.request)) {
                // print the ioctl request label
                if (cmd2label[this.request] == undefined)
                    console.log(this.request.toString(16));
                else
                    console.log(cmd2label[this.request]);

                console.log("ioctl called from:\n" +
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n") + "\n");


            }
        }

        if (this.request == QSEECOM_IOCTL_SEND_CMD_REQ) {
            // get references to member
            this.qseecom_send_cmd_req = ptr(args[2])
            // struct sz is encoded in request, get it
            var sz = get_struct_size(this.request)
            // init structure on host
            send({
                "type": "struct",
                "name": "qseecom_send_cmd_req",
                "cmd": cmd2label[QSEECOM_IOCTL_SEND_CMD_REQ],
                "dump_id": DUMP_ID
            })
            dump_qseecom_send_cmd_req(this.qseecom_send_cmd_req, sz, true);
        } else if (this.request == QSEECOM_IOCTL_SEND_MODFD_CMD_REQ) {
            // get references to member
            this.qseecom_send_modfd_cmd_req = ptr(args[2])
            // struct sz is encoded in request, get it
            var sz = get_struct_size(this.request)
            // init structure on host
            send({
                "type": "struct",
                "name": "qseecom_send_modfd_cmd_req",
                "cmd": cmd2label[QSEECOM_IOCTL_SEND_MODFD_CMD_REQ],
                "dump_id": DUMP_ID
            })
            dump_qseecom_send_modfd_cmd_req(this.qseecom_send_modfd_cmd_req, sz, true);
        } else if (this.request == COMPAT_QSEECOM_IOCTL_SEND_CMD_REQ) {
            // get references to member
            this.compat_qseecom_send_cmd_req = ptr(args[2])
            // struct sz is encoded in request, get it
            var sz = get_struct_size(this.request)
            // init structure on host
            send({
                "type": "struct",
                "name": "compat_qseecom_send_cmd_req",
                "cmd": cmd2label[COMPAT_QSEECOM_IOCTL_SEND_CMD_REQ],
                "dump_id": DUMP_ID
            })
            dump_compat_qseecom_send_cmd_req(this.compat_qseecom_send_cmd_req, sz, true);
        } else if (this.request == COMPAT_QSEECOM_IOCTL_SEND_MODFD_CMD_REQ) {
            // get references to member
            this.compat_qseecom_send_modfd_cmd_req = ptr(args[2])
            // struct sz is encoded in request, get it
            var sz = get_struct_size(this.request)
            // init structure on host
            send({
                "type": "struct",
                "name": "compat_qseecom_send_modfd_cmd_req",
                "cmd": cmd2label[COMPAT_QSEECOM_IOCTL_SEND_MODFD_CMD_REQ],
                "dump_id": DUMP_ID
            })
            dump_compat_qseecom_send_modfd_cmd_req(this.compat_qseecom_send_modfd_cmd_req, sz, true);
        } else if (this.request == QSEECOM_IOCTL_SET_MEM_PARAM_REQ) {
            this.qseecom_ioctl_set_mem_param_req = ptr(args[2])
            //console.log("---> in mem param req!!!!!!!!!!!")

            /*
            struct qseecom_set_sb_mem_param_req {
                int32_t ifd_data_fd;
                void *virt_sb_base;
                uint32_t sb_len;
            };
             */
            var sz = get_struct_size(this.request)
            var curr_ptr = this.qseecom_ioctl_set_mem_param_req.add(8)
            var buf = Memory.readPointer(curr_ptr)

            curr_ptr = this.qseecom_ioctl_set_mem_param_req.add(2 * 8)
            var buf_len = Memory.readU32(curr_ptr)

            send({
                "type": "struct",
                "name": "qseecom_set_mem_param_req",
                "cmd": cmd2label[QSEECOM_IOCTL_SET_MEM_PARAM_REQ],
                "addr": buf,
                "size": buf_len,
                "dump_id": DUMP_ID
            })
        } else if (this.request == COMPAT_QSEECOM_IOCTL_SET_MEM_PARAM_REQ) {
            this.compat_qseecom_ioctl_set_mem_param_req = ptr(args[2])
            //console.log("---> in mem param req!!!!!!!!!!!")

            /*
            struct compat_qseecom_set_sb_mem_param_req {
                    compat_long_t ifd_data_fd;
                    compat_uptr_t virt_sb_base;
                    compat_ulong_t sb_len;
            };
             */
            var sz = get_struct_size(this.request);
            var curr_ptr = this.compat_qseecom_ioctl_set_mem_param_req.add(4);
            var buf = new NativePointer(Memory.readU32(curr_ptr));
            curr_ptr = this.compat_qseecom_ioctl_set_mem_param_req.add(2 * 4);
            var buf_len = Memory.readU32(curr_ptr);

            send({
                "type": "struct",
                "name": "compat_qseecom_set_mem_param_req",
                "cmd": cmd2label[COMPAT_QSEECOM_IOCTL_SET_MEM_PARAM_REQ],
                "addr": buf,
                "size": buf_len,
                "dump_id": DUMP_ID
            })
        } else {
            if (get_magic(this.request) == QC_MAGIC) {
                // only print this if it's the TEE driver
                console.log(this.request.toString(16) + " not implemented")
            }
        }

    },
    onLeave: function (retval) {

        if (this.request == QSEECOM_IOCTL_SEND_CMD_REQ) {
            console.log("return code: " + retval);
            // struct sz is encoded in request
            var sz = get_struct_size(this.request)
            dump_qseecom_send_cmd_req(this.qseecom_send_cmd_req, sz, false);
            send({ "type": "done", "dump_id": DUMP_ID })
            DUMP_ID += 1
        } else if (this.request == QSEECOM_IOCTL_SEND_MODFD_CMD_REQ) {
            console.log("return code: " + retval);
            // struct sz is encoded in request
            var sz = get_struct_size(this.request)
            dump_qseecom_send_modfd_cmd_req(this.qseecom_send_modfd_cmd_req, sz, false);
            send({ "type": "done", "dump_id": DUMP_ID })
            DUMP_ID += 1
        } else if (this.request == COMPAT_QSEECOM_IOCTL_SEND_CMD_REQ) {
            console.log("return code: " + retval);
            // struct sz is encoded in request
            var sz = get_struct_size(this.request)
            dump_compat_qseecom_send_cmd_req(this.compat_qseecom_send_cmd_req, sz, false);
            send({ "type": "done", "dump_id": DUMP_ID })
            DUMP_ID += 1
        } else if (this.request == COMPAT_QSEECOM_IOCTL_SEND_MODFD_CMD_REQ) {
            console.log("return code: " + retval);
            // struct sz is encoded in request
            var sz = get_struct_size(this.request)
            dump_compat_qseecom_send_modfd_cmd_req(this.compat_qseecom_send_modfd_cmd_req, sz, false);
            send({ "type": "done", "dump_id": DUMP_ID })
            DUMP_ID += 1
        }
    }
});

Interceptor.attach(mmap, {
    onEnter: function (args) {
        var addr = args[0];
        this.len = args[1];
        var prot = args[2];
        var flags = args[3];
        this.mmapFD = args[4];
        var offset = args[5];
        console.log('mmap(' + addr + ', ' + this.len + ', ' + prot + ', ' + flags + ', ' + this.mmapFD + ', ' + offset + ')');
    },
    onLeave: function (ret) {
        // remember the mmap mapping of the filedescriptor to a virtual address
        console.log('\tret: ' + ret);
        if (parseInt(ret) > 0) {
            // force javascript to copy the string object
            var curPtr = ptr(ret);
            fd_to_addr[parseInt(this.mmapFD)] = [curPtr, parseInt(this.len)];
            console.log("ADDED: fd " + parseInt(this.mmapFD) + " addr " + fd_to_addr[parseInt(this.mmapFD)] + "\n");
        }
    }
});
