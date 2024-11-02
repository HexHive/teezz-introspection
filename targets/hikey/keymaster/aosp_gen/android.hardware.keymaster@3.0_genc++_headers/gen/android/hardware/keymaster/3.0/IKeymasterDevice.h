#ifndef HIDL_GENERATED_ANDROID_HARDWARE_KEYMASTER_V3_0_IKEYMASTERDEVICE_H
#define HIDL_GENERATED_ANDROID_HARDWARE_KEYMASTER_V3_0_IKEYMASTERDEVICE_H

#include <android/hardware/keymaster/3.0/types.h>
#include <android/hidl/base/1.0/IBase.h>

#include <android/hidl/manager/1.0/IServiceNotification.h>

#include <hidl/HidlSupport.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>
#include <utils/NativeHandle.h>
#include <utils/misc.h>

namespace android {
namespace hardware {
namespace keymaster {
namespace V3_0 {

struct IKeymasterDevice : public ::android::hidl::base::V1_0::IBase {
    typedef android::hardware::details::i_tag _hidl_tag;

    // Forward declaration for forward reference support:

    /**
     * Keymaster device definition.  For thorough documentation see the implementer's reference, at
     * https://source.android.com/security/keystore/implementer-ref.html
     */
    virtual bool isRemote() const override { return false; }


    using getHardwareFeatures_cb = std::function<void(bool isSecure, bool supportsEllipticCurve, bool supportsSymmetricCryptography, bool supportsAttestation, bool supportsAllDigests, const ::android::hardware::hidl_string& keymasterName, const ::android::hardware::hidl_string& keymasterAuthorName)>;
    /**
     * Returns information about the underlying keymaster hardware.
     * 
     * @return isSecure is true if keys are stored and never leave secure hardware (Trusted
     *             Execution Environment or similar). CDD requires that all devices initially
     *             launched with Marshmallow or later must have secure hardware.
     * 
     * @return supportsEllipticCurve is true if the hardware supports Elliptic Curve cryptography
     *             with the NIST curves (P-224, P-256, P-384, and P-521). CDD requires that all
     *             devices initially launched with Nougat or later must support Elliptic Curve
     *             cryptography.
     * 
     * @return supportsSymmetricCryptography is true if the hardware supports symmetric
     *             cryptography, including AES and HMAC. CDD requires that all devices initially
     *             launched with Nougat or later must support hardware enforcement of Keymaster
     *             authorizations.
     * 
     * @return supportsAttestation is true if the hardware supports generation of Keymaster public
     *             key attestation certificates, signed with a key injected in a secure
     *             environment. CDD requires that all devices initially launched with Android O or
     *             later must support hardware attestation.
     * 
     * @return supportsAllDigests is true if the hardware supports all keymaster digest functions,
     *             namely ND-5, SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512. CDD requires that all
     *             devices launched initially with Android O or later must support all digests.
     * 
     * @return keymasterName is the name of the keymaster implementation.
     * 
     * @return keymasterAuthorName is the name of the author of the keymaster implementation
     *             (generally this should be the name of an organization, not an individual.)
     */
    virtual ::android::hardware::Return<void> getHardwareFeatures(getHardwareFeatures_cb _hidl_cb) = 0;

    /**
     * Adds entropy to the RNG used by keymaster. Entropy added through this method is guaranteed
     * not to be the only source of entropy used, and the mixing function is required to be secure,
     * in the sense that if the RNG is seeded (from any source) with any data the attacker cannot
     * predict (or control), then the RNG output is indistinguishable from random. Thus, if the
     * entropy from any source is good, the output must be good.
     * 
     * @param data Bytes to be mixed into the RNG.
     * 
     * @return error See the ErrorCode enum in types.hal.
     */
    virtual ::android::hardware::Return<::android::hardware::keymaster::V3_0::ErrorCode> addRngEntropy(const ::android::hardware::hidl_vec<uint8_t>& data) = 0;

    using generateKey_cb = std::function<void(::android::hardware::keymaster::V3_0::ErrorCode error, const ::android::hardware::hidl_vec<uint8_t>& keyBlob, const ::android::hardware::keymaster::V3_0::KeyCharacteristics& keyCharacteristics)>;
    /**
     * Generates a key, or key pair, returning a key blob and/or a description of the key.
     * 
     * @param keyParams Key generation parameters are defined as keymaster tag/value pairs, provided
     *             in params. See Tag in types.hal for the full list.
     * 
     * @return error See the ErrorCode enum in types.hal.
     * 
     * @return keyBlob Opaque, encrypted descriptor of the generated key, which generally contains a
     *             copy of the key material, wrapped in a key unavailable outside secure hardware.
     * 
     * @return keyCharacteristics Description of the generated key.  See KeyCharacteristis in
     *             types.hal.
     */
    virtual ::android::hardware::Return<void> generateKey(const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& keyParams, generateKey_cb _hidl_cb) = 0;

    using importKey_cb = std::function<void(::android::hardware::keymaster::V3_0::ErrorCode error, const ::android::hardware::hidl_vec<uint8_t>& keyBlob, const ::android::hardware::keymaster::V3_0::KeyCharacteristics& keyCharacteristics)>;
    /**
     * Imports a key, or key pair, returning a key blob and/or a description of the key.
     * 
     * @param keyParams Key generation parameters are defined as keymaster tag/value pairs, provided
     *             in params.  See Tag for the full list.
     * 
     * @param keyFormat The format of the key material to import. See KeyFormat in types.hal.
     * 
     * @pram keyData The key material to import, in the format specifed in keyFormat.
     * 
     * @return error See the ErrorCode enum.
     * 
     * @return keyBlob Opaque, encrypted descriptor of the generated key, which will generally
     *             contain a copy of the key material, wrapped in a key unavailable outside secure
     *             hardware.
     * 
     * @return keyCharacteristics Decription of the generated key.  See KeyCharacteristis.
     * 
     * @return error See the ErrorCode enum.
     */
    virtual ::android::hardware::Return<void> importKey(const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& params, ::android::hardware::keymaster::V3_0::KeyFormat keyFormat, const ::android::hardware::hidl_vec<uint8_t>& keyData, importKey_cb _hidl_cb) = 0;

    using getKeyCharacteristics_cb = std::function<void(::android::hardware::keymaster::V3_0::ErrorCode error, const ::android::hardware::keymaster::V3_0::KeyCharacteristics& keyCharacteristics)>;
    /**
     * Returns the characteristics of the specified key, if the keyBlob is valid (implementations
     * must fully validate the integrity of the key).
     * 
     * @param keyBlob The opaque descriptor returned by generateKey() or importKey();
     * 
     * @param clientId An opaque byte string identifying the client. This value must match the
     *             Tag::APPLICATION_ID data provided during key generation/import.  Without the
     *             correct value it must be cryptographically impossible for the secure hardware to
     *             obtain the key material.
     * 
     * @param appData An opaque byte string provided by the application. This value must match the
     *             Tag::APPLICATION_DATA data provided during key generation/import.  Without the
     *             correct value it must be cryptographically impossible for the secure hardware to
     *             obtain the key material.
     * 
     * @return error See the ErrorCode enum in types.hal.
     * 
     * @return keyCharacteristics Decription of the generated key.  See KeyCharacteristis in
     *             types.hal.
     */
    virtual ::android::hardware::Return<void> getKeyCharacteristics(const ::android::hardware::hidl_vec<uint8_t>& keyBlob, const ::android::hardware::hidl_vec<uint8_t>& clientId, const ::android::hardware::hidl_vec<uint8_t>& appData, getKeyCharacteristics_cb _hidl_cb) = 0;

    using exportKey_cb = std::function<void(::android::hardware::keymaster::V3_0::ErrorCode error, const ::android::hardware::hidl_vec<uint8_t>& keyMaterial)>;
    /**
     * Exports a public key, returning the key in the specified format.
     * 
     * @parm keyFormat The format used for export. See KeyFormat in types.hal.
     * 
     * @param keyBlob The opaque descriptor returned by generateKey() or importKey().  The
     *             referenced key must be asymmetric.
     * 
     * @param clientId An opaque byte string identifying the client. This value must match the
     *             Tag::APPLICATION_ID data provided during key generation/import.  Without the
     *             correct value it must be cryptographically impossible for the secure hardware to
     *             obtain the key material.
     * 
     * @param appData An opaque byte string provided by the application. This value must match the
     *             Tag::APPLICATION_DATA data provided during key generation/import.  Without the
     *             correct value it must be cryptographically impossible for the secure hardware to
     *             obtain the key material.
     * 
     * @return error See the ErrorCode enum in types.hal.
     * 
     * @return keyMaterial The public key material in PKCS#8 format.
     */
    virtual ::android::hardware::Return<void> exportKey(::android::hardware::keymaster::V3_0::KeyFormat keyFormat, const ::android::hardware::hidl_vec<uint8_t>& keyBlob, const ::android::hardware::hidl_vec<uint8_t>& clientId, const ::android::hardware::hidl_vec<uint8_t>& appData, exportKey_cb _hidl_cb) = 0;

    using attestKey_cb = std::function<void(::android::hardware::keymaster::V3_0::ErrorCode error, const ::android::hardware::hidl_vec<::android::hardware::hidl_vec<uint8_t>>& certChain)>;
    /**
     * Generates a signed X.509 certificate chain attesting to the presence of keyToAttest in
     * keymaster. The certificate will contain an extension with OID 1.3.6.1.4.1.11129.2.1.17 and
     * value defined in:
     * 
     *     https://developer.android.com/training/articles/security-key-attestation.html.
     * 
     * @param keyToAttest The opaque descriptor returned by generateKey() or importKey().  The
     *             referenced key must be asymmetric.
     * 
     * @param attestParams Parameters for the attestation, notably Tag::ATTESTATION_CHALLENGE.
     * 
     * @return error See the ErrorCode enum in types.hal.
     */
    virtual ::android::hardware::Return<void> attestKey(const ::android::hardware::hidl_vec<uint8_t>& keyToAttest, const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& attestParams, attestKey_cb _hidl_cb) = 0;

    using upgradeKey_cb = std::function<void(::android::hardware::keymaster::V3_0::ErrorCode error, const ::android::hardware::hidl_vec<uint8_t>& upgradedKeyBlob)>;
    /**
     * Upgrades an old key. Keys can become "old" in two ways: Keymaster can be upgraded to a new
     * version, or the system can be updated to invalidate the OS version and/or patch level. In
     * either case, attempts to use an old key with getKeyCharacteristics(), exportKey(),
     * attestKey() or begin() will result in keymaster returning
     * ErrorCode::KEY_REQUIRES_UPGRADE. This method must then be called to upgrade the key.
     * 
     * @param keyBlobToUpgrade The opaque descriptor returned by generateKey() or importKey();
     * 
     * @param upgradeParams A parameter list containing any parameters needed to complete the
     *             upgrade, including Tag::APPLICATION_ID and Tag::APPLICATION_DATA.
     * 
     * @return error See the ErrorCode enum.
     */
    virtual ::android::hardware::Return<void> upgradeKey(const ::android::hardware::hidl_vec<uint8_t>& keyBlobToUpgrade, const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& upgradeParams, upgradeKey_cb _hidl_cb) = 0;

    /**
     * Deletes the key, or key pair, associated with the key blob. After calling this function it
     * will be impossible to use the key for any other operations. May be applied to keys from
     * foreign roots of trust (keys not usable under the current root of trust).
     * 
     * This is a NOP for keys that don't have rollback protection.
     * 
     * @param keyBlobToUpgrade The opaque descriptor returned by generateKey() or importKey();
     * 
     * @return error See the ErrorCode enum.
     */
    virtual ::android::hardware::Return<::android::hardware::keymaster::V3_0::ErrorCode> deleteKey(const ::android::hardware::hidl_vec<uint8_t>& keyBlob) = 0;

    /**
     * Deletes all keys in the hardware keystore. Used when keystore is reset completely. After
     * calling this function it will be impossible to use any previously generated or imported key
     * blobs for any operations.
     * 
     * This is a NOP if keys don't have rollback protection.
     * 
     * @return error See the ErrorCode enum.
     */
    virtual ::android::hardware::Return<::android::hardware::keymaster::V3_0::ErrorCode> deleteAllKeys() = 0;

    /**
     * Destroys knowledge of the device's ids. This prevents all device id attestation in the
     * future. The destruction must be permanent so that not even a factory reset will restore the
     * device ids.
     * 
     * Device id attestation may be provided only if this method is fully implemented, allowing the
     * user to permanently disable device id attestation. If this cannot be guaranteed, the device
     * must never attest any device ids.
     * 
     * This is a NOP if device id attestation is not supported.
     * 
     * @return error See the ErrorCode enum.
     */
    virtual ::android::hardware::Return<::android::hardware::keymaster::V3_0::ErrorCode> destroyAttestationIds() = 0;

    using begin_cb = std::function<void(::android::hardware::keymaster::V3_0::ErrorCode error, const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& outParams, uint64_t operationHandle)>;
    /**
     * Begins a cryptographic operation using the specified key. If all is well, begin() will return
     * ErrorCode::OK and create an operation handle which must be passed to subsequent calls to
     * update(), finish() or abort().
     * 
     * It is critical that each call to begin() be paired with a subsequent call to finish() or
     * abort(), to allow the keymaster implementation to clean up any internal operation state.
     * Failure to do this may leak internal state space or other internal resources and may
     * eventually cause begin() to return ErrorCode::TOO_MANY_OPERATIONS when it runs out of space
     * for operations. Any result other than ErrorCode::OK from begin(), update() or finish()
     * implicitly aborts the operation, in which case abort() need not be called (and will return
     * ErrorCode::INVALID_OPERATION_HANDLE if called).
     * 
     * @param purpose The purpose of the operation, one of KeyPurpose::ENCRYPT, KeyPurpose::DECRYPT,
     *             KeyPurpose::SIGN or KeyPurpose::VERIFY. Note that for AEAD modes, encryption and
     *             decryption imply signing and verification, respectively, but must be specified as
     *             KeyPurpose::ENCRYPT and KeyPurpose::DECRYPT.
     * 
     * @param keyBlob The opaque key descriptor returned by generateKey() or importKey().  The key
     *             must have a purpose compatible with purpose and all of its usage requirements
     *             must be satisfied, or begin() will return an appropriate error code.
     * 
     * @param inParams Additional parameters for the operation. This is typically used to provide
     *             authentication data, with Tag::AUTH_TOKEN. If Tag::APPLICATION_ID or
     *             Tag::APPLICATION_DATA were provided during generation, they must be provided
     *             here, or the operation will fail with ErrorCode::INVALID_KEY_BLOB. For operations
     *             that require a nonce or IV, on keys that were generated with Tag::CALLER_NONCE,
     *             inParams may contain a tag Tag::NONCE.
     * 
     * @return error See the ErrorCode enum in types.hal.
     * 
     * @return outParams Output parameters. Used to return additional data from the operation
     *             initialization, notably to return the IV or nonce from operations that generate
     *             an IV or nonce.
     * 
     * @return operationHandle The newly-created operation handle which must be passed to update(),
     *             finish() or abort().
     */
    virtual ::android::hardware::Return<void> begin(::android::hardware::keymaster::V3_0::KeyPurpose purpose, const ::android::hardware::hidl_vec<uint8_t>& key, const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& inParams, begin_cb _hidl_cb) = 0;

    using update_cb = std::function<void(::android::hardware::keymaster::V3_0::ErrorCode error, uint32_t inputConsumed, const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& outParams, const ::android::hardware::hidl_vec<uint8_t>& output)>;
    /**
     * Provides data to, and possibly receives output from, an ongoing cryptographic operation begun
     * with begin().
     * 
     * If operationHandle is invalid, update() will return ErrorCode::INVALID_OPERATION_HANDLE.
     * 
     * update() may not consume all of the data provided in the data buffer. update() will return
     * the amount consumed in inputConsumed. The caller may provide the unconsumed data in a
     * subsequent call.
     * 
     * @param operationHandle The operation handle returned by begin().
     * 
     * @param inParams Additional parameters for the operation. For AEAD modes, this is used to
     *             specify Tag::ADDITIONAL_DATA. Note that additional data may be provided in
     *             multiple calls to update(), but only until input data has been provided.
     * 
     * @param input Data to be processed, per the parameters established in the call to begin().
     *             Note that update() may or may not consume all of the data provided. See
     *             inputConsumed.
     * 
     * @return error See the ErrorCode enum in types.hal.
     * 
     * @return inputConsumed Amount of data that was consumed by update(). If this is less than the
     *             amount provided, the caller may provide the remainder in a subsequent call to
     *             update() or finish().
     * 
     * @return outParams Output parameters, used to return additional data from the operation The
     *             caller takes ownership of the output parameters array and must free it with
     *             keymaster_free_param_set().
     * 
     * @return output The output data, if any.
     */
    virtual ::android::hardware::Return<void> update(uint64_t operationHandle, const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& inParams, const ::android::hardware::hidl_vec<uint8_t>& input, update_cb _hidl_cb) = 0;

    using finish_cb = std::function<void(::android::hardware::keymaster::V3_0::ErrorCode error, const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& outParams, const ::android::hardware::hidl_vec<uint8_t>& output)>;
    /**
     * Finalizes a cryptographic operation begun with begin() and invalidates operationHandle.
     * 
     * @param operationHandle The operation handle returned by begin(). This handle will be
     *             invalid when finish() returns.
     * 
     * @param inParams Additional parameters for the operation. For AEAD modes, this is used to
     *             specify Tag::ADDITIONAL_DATA, but only if no input data was provided to update().
     * 
     * @param input Data to be processed, per the parameters established in the call to
     *             begin(). finish() must consume all provided data or return
     *             ErrorCode::INVALID_INPUT_LENGTH.
     * 
     * @param signature The signature to be verified if the purpose specified in the begin() call
     *             was KeyPurpose::VERIFY.
     * 
     * @return error See the ErrorCode enum in types.hal.
     * 
     * @return outParams Any output parameters generated by finish().
     * 
     * @return output The output data, if any.
     */
    virtual ::android::hardware::Return<void> finish(uint64_t operationHandle, const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& inParams, const ::android::hardware::hidl_vec<uint8_t>& input, const ::android::hardware::hidl_vec<uint8_t>& signature, finish_cb _hidl_cb) = 0;

    /**
     * Aborts a cryptographic operation begun with begin(), freeing all internal resources and
     * invalidating operationHandle.
     * 
     * @param operationHandle The operation handle returned by begin(). This handle will be
     *             invalid when abort() returns.
     * 
     * @return error See the ErrorCode enum in types.hal.
     */
    virtual ::android::hardware::Return<::android::hardware::keymaster::V3_0::ErrorCode> abort(uint64_t operationHandle) = 0;

    using interfaceChain_cb = std::function<void(const ::android::hardware::hidl_vec<::android::hardware::hidl_string>& descriptors)>;
    virtual ::android::hardware::Return<void> interfaceChain(interfaceChain_cb _hidl_cb) override;

    virtual ::android::hardware::Return<void> debug(const ::android::hardware::hidl_handle& fd, const ::android::hardware::hidl_vec<::android::hardware::hidl_string>& options) override;

    using interfaceDescriptor_cb = std::function<void(const ::android::hardware::hidl_string& descriptor)>;
    virtual ::android::hardware::Return<void> interfaceDescriptor(interfaceDescriptor_cb _hidl_cb) override;

    using getHashChain_cb = std::function<void(const ::android::hardware::hidl_vec<::android::hardware::hidl_array<uint8_t, 32>>& hashchain)>;
    virtual ::android::hardware::Return<void> getHashChain(getHashChain_cb _hidl_cb) override;

    virtual ::android::hardware::Return<void> setHALInstrumentation() override;

    virtual ::android::hardware::Return<bool> linkToDeath(const ::android::sp<::android::hardware::hidl_death_recipient>& recipient, uint64_t cookie) override;

    virtual ::android::hardware::Return<void> ping() override;

    using getDebugInfo_cb = std::function<void(const ::android::hidl::base::V1_0::DebugInfo& info)>;
    virtual ::android::hardware::Return<void> getDebugInfo(getDebugInfo_cb _hidl_cb) override;

    virtual ::android::hardware::Return<void> notifySyspropsChanged() override;

    virtual ::android::hardware::Return<bool> unlinkToDeath(const ::android::sp<::android::hardware::hidl_death_recipient>& recipient) override;
    // cast static functions
    static ::android::hardware::Return<::android::sp<::android::hardware::keymaster::V3_0::IKeymasterDevice>> castFrom(const ::android::sp<::android::hardware::keymaster::V3_0::IKeymasterDevice>& parent, bool emitError = false);
    static ::android::hardware::Return<::android::sp<::android::hardware::keymaster::V3_0::IKeymasterDevice>> castFrom(const ::android::sp<::android::hidl::base::V1_0::IBase>& parent, bool emitError = false);

    static const char* descriptor;

    static ::android::sp<IKeymasterDevice> tryGetService(const std::string &serviceName="default", bool getStub=false);
    static ::android::sp<IKeymasterDevice> tryGetService(const char serviceName[], bool getStub=false)  { std::string str(serviceName ? serviceName : "");      return tryGetService(str, getStub); }
    static ::android::sp<IKeymasterDevice> tryGetService(const ::android::hardware::hidl_string& serviceName, bool getStub=false)  { std::string str(serviceName.c_str());      return tryGetService(str, getStub); }
    static ::android::sp<IKeymasterDevice> tryGetService(bool getStub) { return tryGetService("default", getStub); }
    static ::android::sp<IKeymasterDevice> getService(const std::string &serviceName="default", bool getStub=false);
    static ::android::sp<IKeymasterDevice> getService(const char serviceName[], bool getStub=false)  { std::string str(serviceName ? serviceName : "");      return getService(str, getStub); }
    static ::android::sp<IKeymasterDevice> getService(const ::android::hardware::hidl_string& serviceName, bool getStub=false)  { std::string str(serviceName.c_str());      return getService(str, getStub); }
    static ::android::sp<IKeymasterDevice> getService(bool getStub) { return getService("default", getStub); }
    __attribute__ ((warn_unused_result))::android::status_t registerAsService(const std::string &serviceName="default");
    static bool registerForNotifications(
            const std::string &serviceName,
            const ::android::sp<::android::hidl::manager::V1_0::IServiceNotification> &notification);
};

static inline std::string toString(const ::android::sp<::android::hardware::keymaster::V3_0::IKeymasterDevice>& o) {
    std::string os = "[class or subclass of ";
    os += ::android::hardware::keymaster::V3_0::IKeymasterDevice::descriptor;
    os += "]";
    os += o->isRemote() ? "@remote" : "@local";
    return os;
}


}  // namespace V3_0
}  // namespace keymaster
}  // namespace hardware
}  // namespace android

#endif  // HIDL_GENERATED_ANDROID_HARDWARE_KEYMASTER_V3_0_IKEYMASTERDEVICE_H
