var ioctl = Module.findExportByName(null, "ioctl");

var OPTEE_MAGIC = 0xa4;
var PTR_SZ = 8;

// dirty hack to prevent collisions with high-lvl dump ids
// TODO: we should fix this in `dualrecorder`
var DUMP_ID = 1 << 16;
var DEBUG = true;

var __u32 = 4;
var __u64 = 8;

/*
 * These constants are the commands given to the ioctl-command handler.
 * E.g., request in `int ioctl(int fd, unsigned long request, ...);`.
 * The commands are dependent on the size of the data type passed to the kernel.
 * If this data type changes, the command changes too.
 * This is why we need to spcify the sizes first.
 */
var TEE_IOC_OPEN_SESSION = 0x8010a402;
var TEE_IOC_INVOKE = 0x8010a403;
var TEE_IOC_CLOSE_SESSION = 0x8004a405;
var TEE_IOC_SUPPL_RECV = 0x8010a406;
var TEE_IOC_SUPPL_SEND = 0x8010a407;
var TEE_IOC_SHM_REGISTER = 0xc018a409;

// convenience dictionary to map cmd ids (int) to strings
var CMD2LABEL = {};
CMD2LABEL[TEE_IOC_OPEN_SESSION] = "TEE_IOC_OPEN_SESSION";
CMD2LABEL[TEE_IOC_INVOKE] = "TEE_IOC_INVOKE";
CMD2LABEL[TEE_IOC_CLOSE_SESSION] = "TEE_IOC_CLOSE_SESSION";
CMD2LABEL[TEE_IOC_SHM_REGISTER] = "TEE_IOC_SHM_REGISTER";
CMD2LABEL[TEE_IOC_SUPPL_RECV] = "TEE_IOC_SUPPL_RECV";
CMD2LABEL[TEE_IOC_SUPPL_SEND] = "TEE_IOC_SUPPL_SEND";


// param types
var TEE_IOCTL_PARAM_ATTR_TYPE_NONE = 0;
var TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT = 1;
var TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT = 2;
var TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT = 3;
var TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT = 5;
var TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT = 6;
var TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT = 7;


// convenience dictionary to map param types (int) to strings
var TYPE2LABEL = {};
TYPE2LABEL[TEE_IOCTL_PARAM_ATTR_TYPE_NONE] = "TEE_IOCTL_PARAM_ATTR_TYPE_NONE";
TYPE2LABEL[TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT] = "TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT";
TYPE2LABEL[TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT] = "TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT";
TYPE2LABEL[TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT] = "TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT";
TYPE2LABEL[TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT] = "TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT";
TYPE2LABEL[TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT] = "TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT";
TYPE2LABEL[TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT] = "TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT";

// dictionary of currently TEE-registered shared memory regions
// we use the shared memory identifier as a key to reference a dictionary
// holding { "addr": addr, "length": length, "flags": flags, "fd": retval };
var SHMS = {}

function get_struct_size(cmd) {
  return (cmd & 0x00ff0000) >> 16;
}

function is_optee(cmd) {
  if (get_magic(cmd) == OPTEE_MAGIC)
    return true;
  else
    return false;
}

function get_magic(cmd) {
  return (cmd & 0x0000ff00) >> 8;
}

function dump_tee_ioctl_invoke_arg(tee_ioctl_buf_data, size, is_on_enter) {
  /*
   *
  struct tee_ioctl_buf_data {
          __u64 buf_ptr;
          __u64 buf_len;
  };

  struct tee_ioctl_invoke_arg {
          __u32 func;
          __u32 session;
          __u32 cancel_id;
          __u32 ret;
          __u32 ret_origin;
          __u32 num_params;
          // num_params tells the actual number of element in params
          struct tee_ioctl_param params[];
  };
  */

  var tee_ioctl_invoke_arg_sz = Memory.readU64(tee_ioctl_buf_data.add(8));
  var tee_ioctl_invoke_arg = ptr(Memory.readU64(tee_ioctl_buf_data));

  console.log("size: " + tee_ioctl_invoke_arg_sz);
  console.log("ptr: " + tee_ioctl_invoke_arg);

  var hd = hexdump(tee_ioctl_invoke_arg,
    { length: tee_ioctl_invoke_arg_sz, header: true, ansi: true });
  //console.log(hd);

  var func = Memory.readU32(tee_ioctl_invoke_arg, 4);

  var session_id = Memory.readByteArray(tee_ioctl_invoke_arg.add(4), 4);
  var ret = Memory.readByteArray(tee_ioctl_invoke_arg.add(12), 4);
  var ret_origin = Memory.readByteArray(tee_ioctl_invoke_arg.add(16), 4);
  var num_params = Memory.readU32(tee_ioctl_invoke_arg.add(20), 4);
  var params_ptr = tee_ioctl_invoke_arg.add(24);

  //console.log("func: " + func);
  //console.log("session: " + session_id);
  //console.log("num_params: " + num_params);

  var params = {}
  for (var i = 0; i < 4; i++) {
    params[i] = {}
    var param_ptr = params_ptr.add(i * 4 * PTR_SZ);
    params[i]["attr"] = Memory.readU64(param_ptr);
    params[i]["param_a"] = param_ptr.add(PTR_SZ);
    params[i]["param_b"] = param_ptr.add(2 * PTR_SZ);
    //params[i]["param_b_bytes"] = Memory.readByteArray(param_ptr, PTR_SZ)
    params[i]["param_c"] = param_ptr.add(3 * PTR_SZ);
  }

  for (var i = 0; i < 4; i++) {

    var param_ptr = params_ptr.add(i * 4 * PTR_SZ);
    var param_type = parseInt(params[i]["attr"]);

    var hd = hexdump(param_ptr,
      { length: 4 * PTR_SZ, header: true, ansi: true });
    console.log(hd);

    switch (param_type) {
      case TEE_IOCTL_PARAM_ATTR_TYPE_NONE:
        console.log("NONE")
        break;
      case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
      case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
      case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
        console.log("VAL")
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
      case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
      case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
      case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
        console.log("MEMREF dump_id " + DUMP_ID + " param no " + i + " memref " + TYPE2LABEL[param_type]);
        //if(0 != params[i]["param_c"].and(uint64(0xffff000000000000)).compare(uint64(0))){
        //    console.log("kernel address! (" + params[i]["param_c"].toString(16) + ")")
        //    break;
        //}

        // get offset
        var offset = 0;
        if (params[i]["param_a"] != 0) {
          params[i]["param_a_data"] = Memory.readByteArray(ptr(params[i]["param_a"]), __u64);
          offset = Memory.readU64(ptr(params[i]["param_a"]));
        } else {
          console.log("ptr to memref buffer missing.")
        }

        // get size
        var buf_sz = null;
        if (params[i]["param_b"] != 0) {
          params[i]["param_b_data"] = Memory.readByteArray(ptr(params[i]["param_b"]), __u64);
          buf_sz = Memory.readU64(ptr(params[i]["param_b"]));
        } else {
          console.log("size for memref missing.");
          break;
        }

        // get shm id
        var shm_id = null;
        if (params[i]["param_c"] != 0) {
          params[i]["param_c_data"] = params[i]["param_c_bytes"];
          shm_id = Memory.readU64(ptr(params[i]["param_c"]));
        } else {
          //console.log("offset for memref missing.")
          params[i]["param_c_data"] = null;
        }

        if (SHMS[shm_id]) {
          //console.log(Object.keys(SHMS));
          var addr = ptr(SHMS[shm_id]["addr"]);
          //console.log("shm_id " + shm_id + ": Reading from " + addr + " at offset " + offset + " with sz " + buf_sz);
          params[i]["param_data"] = Memory.readByteArray(addr.add(offset), buf_sz);
          //var hd = hexdump(addr.add(offset),
          //  { length: buf_sz, header : true, ansi : true });
          //console.log(hd);
        }

        break;
      default:
        console.log("param type " + param_type + " not known.");
        break;
    }
  }

  var ctx_data = Memory.readByteArray(tee_ioctl_invoke_arg, tee_ioctl_invoke_arg_sz);
  send({ "type": "tee_ioctl_invoke_arg", "on_enter": is_on_enter, "dump_id": DUMP_ID }, ctx_data);
  for (var i = 0; i < 4; i++) {
    send({ "type": "param_" + i + "_a", "on_enter": is_on_enter, "dump_id": DUMP_ID }, params[i]["param_a_data"]);
    send({ "type": "param_" + i + "_b", "on_enter": is_on_enter, "dump_id": DUMP_ID }, params[i]["param_b_data"]);
    send({ "type": "param_" + i + "_c", "on_enter": is_on_enter, "dump_id": DUMP_ID }, params[i]["param_c_data"]);
    if (params[i]["param_data"]) {
      send({ "type": "param_" + i + "_data", "on_enter": is_on_enter, "dump_id": DUMP_ID }, params[i]["param_data"]);
    }
  }
}

function handle_tee_ioctl_shm_register(tee_ioctl_shm_register_data, retval) {
  /*
    struct tee_ioctl_shm_register_data {
            __u64 addr;
            __u64 length;
            __u32 flags;
            __s32 id;
    };
  */

  if (retval >= 0) {
    var addr = Memory.readU64(tee_ioctl_shm_register_data);
    var length = Memory.readU64(tee_ioctl_shm_register_data.add(8));
    var flags = Memory.readU32(tee_ioctl_shm_register_data.add(16));
    var id = Memory.readU32(tee_ioctl_shm_register_data.add(20));
    SHMS[id] = { "addr": addr, "length": length, "flags": flags, "fd": retval };
  } else {
    console.log("tee_ioctl_shm_register failed with status code: " + retval);
  }
  return;
}


Interceptor.attach(ioctl, {
  onEnter: function (args) {

    this.request = parseInt(args[1], 16);
    if (is_optee(this.request)) {
      console.log("### onEnter start ###");
    }

    if (DEBUG) {
      if (is_optee(this.request)) {
        // print the ioctl request label
        if (CMD2LABEL[this.request] == undefined) {
          console.log(this.request);
        }
        else
          console.log(CMD2LABEL[this.request]);
      }
    }

    if (this.request == TEE_IOC_INVOKE) {
      //console.log("ioctl called from:\n" +
      //         Thread.backtrace(this.context, Backtracer.ACCURATE)
      //         .map(DebugSymbol.fromAddress).join("\n") + "\n");
      this.argp = ptr(args[2])

      this.size = get_struct_size(this.request);
      send({
        "type": "struct",
        "name": "tee_ioctl_invoke_arg",
        "cmd": CMD2LABEL[TEE_IOC_INVOKE],
        "dump_id": DUMP_ID
      })
      dump_tee_ioctl_invoke_arg(this.argp, this.size, true);
    } else if (this.request == TEE_IOC_SHM_REGISTER) {
      /*
       * We are primarily interested in recording data sent via
       * TEE_IOC_INVOKE ioctls. Unfortunately, OPTEE uses some
       * pre-registered shared memory to communicate with the TEE to
       * to exchange data between CAs and TAs. We have to keep track of this
       * shared memory to record all buffers passed via TEE_IOC_INVOKE 
       * ioctls.
       *
       * In onEnter() we just store the argp reference to later fill the
       * global SHMS dictionary, which tracks the currently registered
       * shared memory regions.
       */
      console.log("Registering shared memory");
      this.argp = ptr(args[2])
      this.size = get_struct_size(this.request);
    } else {
      console.log("Not handling cmd " + this.request.toString(16));
    }


    if (is_optee(this.request)) {
      console.log("### onEnter end ###");
    }
  },
  onLeave: function (retval) {

    if (is_optee(this.request)) {
      console.log("### onLeave start ###");
    }

    if (this.request == TEE_IOC_INVOKE) {
      dump_tee_ioctl_invoke_arg(this.argp, this.size, false);
      send({ "type": "done", "dump_id": DUMP_ID });
      DUMP_ID += 1;
    } else if (this.request == TEE_IOC_SHM_REGISTER) {
      handle_tee_ioctl_shm_register(this.argp, retval);
    } else {
      console.log("Not handling cmd " + this.request.toString(16))
    }

    if (is_optee(this.request)) {
      console.log("### onLeave end ###");
    }
  }
});
