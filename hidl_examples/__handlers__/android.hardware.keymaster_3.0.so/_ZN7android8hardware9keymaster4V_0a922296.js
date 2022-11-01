/**
 * Example hook for HIDL begin.
 *
 * This script uses frida 11.0.0 javascript api. Newer versions are not supported.
 */

{
  /**
   * Called synchronously when about to call _ZN7android8hardware9keymaster4V3_019BpHwKeymasterDevice5beginENS2_10KeyPurposeERKNS0_8hidl_vecIhEERKNS5_INS2_12KeyParameterEEENSt3__18functionIFvNS2_9ErrorCodeESC_mEEE.
   *
   * @this {object} - Object allowing you to store state for use in onLeave.
   * @param {function} log - Call this function with a string to be presented to the user.
   * @param {array} args - Function arguments represented as an array of NativePointer objects.
   * For example use Memory.readUtf8String(args[0]) if the first argument is a pointer to a C string encoded as UTF-8.
   * It is also possible to modify arguments by assigning a NativePointer object to an element of this array.
   * @param {object} state - Object allowing you to keep state across function calls.
   * Only one JavaScript function will execute at a time, so do not worry about race-conditions.
   * However, do not use this to store function arguments across onEnter/onLeave, but instead
   * use "this" which is an object for keeping state local to an invocation.
   */
  onEnter: function (log, args, state) {
    log("hook triggered!");

    /**
     * Parses an hidl_vec from memory
     *
     * @param {NativePointer} hidlVec - Reference to the hidl_vec struct in memory
     * @return {string} - The extracted data hex encoded in a string
     */
    parseHidlVec = function (hidlVec) {
      log("Parsing hidl_vec");

      // get the addresses of the struct members
      var ptr1 = new NativePointer(hidlVec);
      var ptr2 = ptr1.add(Process.pointerSize);
      log("hidl_vec struct at address: " + ptr1);

      // Reading buffer start address and size
      var bufStart = new NativePointer(Memory.readU64(ptr1));
      var bufSize = Memory.readU32(ptr2);
      log("buffer starts at: " + bufStart);
      log("buffer size: " + bufSize);

      // Extracting the data from memory
      var data = "";
      for (var i = 0; i < bufSize; i++) {
        var value = Memory.readU8(bufStart.add(i)).toString(16);
        data += (value.length==1 ? "0" : "") + value + " ";
      }

      return data
    }

    log("_ZN7android8hardware9keymaster4V3_019BpHwKeymasterDevice5beginENS2_10KeyPurposeERKNS0_8hidl_vecIhEERKNS5_INS2_12KeyParameterEEENSt3__18functionIFvNS2_9ErrorCodeESC_mEEE()");
    log("begin(this=" + args[0]
      + ", purpose=" + args[1]
      + ", key=" + args[2]
      + ", inParams=" + args[3]
      + ", _hidl_cb=" + args[4]
      + ")");

    key = parseHidlVec(args[2]);
    log("key: " + key)

    inParams = parseHidlVec(args[3]);
    log("inParams: " + inParams)

  },

  /**
   * Called synchronously when about to return from _ZN7android8hardware9keymaster4V3_019BpHwKeymasterDevice5beginENS2_10KeyPurposeERKNS0_8hidl_vecIhEERKNS5_INS2_12KeyParameterEEENSt3__18functionIFvNS2_9ErrorCodeESC_mEEE.
   *
   * See onEnter for details.
   *
   * @this {object} - Object allowing you to access state stored in onEnter.
   * @param {function} log - Call this function with a string to be presented to the user.
   * @param {NativePointer} retval - Return value represented as a NativePointer object.
   * @param {object} state - Object allowing you to keep state across function calls.
   */
  onLeave: function (log, retval, state) {
  }
}
