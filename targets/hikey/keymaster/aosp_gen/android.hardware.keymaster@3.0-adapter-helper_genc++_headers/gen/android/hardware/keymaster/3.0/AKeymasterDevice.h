#ifndef HIDL_GENERATED_ANDROID_HARDWARE_KEYMASTER_V3_0_AKEYMASTERDEVICE_H
#define HIDL_GENERATED_ANDROID_HARDWARE_KEYMASTER_V3_0_AKEYMASTERDEVICE_H

#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>
namespace android {
namespace hardware {
namespace keymaster {
namespace V3_0 {

class AKeymasterDevice : public ::android::hardware::keymaster::V3_0::IKeymasterDevice {
    public:
    typedef ::android::hardware::keymaster::V3_0::IKeymasterDevice Pure;
    AKeymasterDevice(::android::sp<::android::hardware::keymaster::V3_0::IKeymasterDevice> impl);
    // Methods from ::android::hardware::keymaster::V3_0::IKeymasterDevice follow.
    virtual ::android::hardware::Return<void> getHardwareFeatures(getHardwareFeatures_cb _hidl_cb) override;
    virtual ::android::hardware::Return<::android::hardware::keymaster::V3_0::ErrorCode> addRngEntropy(const ::android::hardware::hidl_vec<uint8_t>& data) override;
    virtual ::android::hardware::Return<void> generateKey(const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& keyParams, generateKey_cb _hidl_cb) override;
    virtual ::android::hardware::Return<void> importKey(const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& params, ::android::hardware::keymaster::V3_0::KeyFormat keyFormat, const ::android::hardware::hidl_vec<uint8_t>& keyData, importKey_cb _hidl_cb) override;
    virtual ::android::hardware::Return<void> getKeyCharacteristics(const ::android::hardware::hidl_vec<uint8_t>& keyBlob, const ::android::hardware::hidl_vec<uint8_t>& clientId, const ::android::hardware::hidl_vec<uint8_t>& appData, getKeyCharacteristics_cb _hidl_cb) override;
    virtual ::android::hardware::Return<void> exportKey(::android::hardware::keymaster::V3_0::KeyFormat keyFormat, const ::android::hardware::hidl_vec<uint8_t>& keyBlob, const ::android::hardware::hidl_vec<uint8_t>& clientId, const ::android::hardware::hidl_vec<uint8_t>& appData, exportKey_cb _hidl_cb) override;
    virtual ::android::hardware::Return<void> attestKey(const ::android::hardware::hidl_vec<uint8_t>& keyToAttest, const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& attestParams, attestKey_cb _hidl_cb) override;
    virtual ::android::hardware::Return<void> upgradeKey(const ::android::hardware::hidl_vec<uint8_t>& keyBlobToUpgrade, const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& upgradeParams, upgradeKey_cb _hidl_cb) override;
    virtual ::android::hardware::Return<::android::hardware::keymaster::V3_0::ErrorCode> deleteKey(const ::android::hardware::hidl_vec<uint8_t>& keyBlob) override;
    virtual ::android::hardware::Return<::android::hardware::keymaster::V3_0::ErrorCode> deleteAllKeys() override;
    virtual ::android::hardware::Return<::android::hardware::keymaster::V3_0::ErrorCode> destroyAttestationIds() override;
    virtual ::android::hardware::Return<void> begin(::android::hardware::keymaster::V3_0::KeyPurpose purpose, const ::android::hardware::hidl_vec<uint8_t>& key, const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& inParams, begin_cb _hidl_cb) override;
    virtual ::android::hardware::Return<void> update(uint64_t operationHandle, const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& inParams, const ::android::hardware::hidl_vec<uint8_t>& input, update_cb _hidl_cb) override;
    virtual ::android::hardware::Return<void> finish(uint64_t operationHandle, const ::android::hardware::hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter>& inParams, const ::android::hardware::hidl_vec<uint8_t>& input, const ::android::hardware::hidl_vec<uint8_t>& signature, finish_cb _hidl_cb) override;
    virtual ::android::hardware::Return<::android::hardware::keymaster::V3_0::ErrorCode> abort(uint64_t operationHandle) override;

    // Methods from ::android::hidl::base::V1_0::IBase follow.

    private:
    ::android::sp<::android::hardware::keymaster::V3_0::IKeymasterDevice> mImpl;
};

}  // namespace V3_0
}  // namespace keymaster
}  // namespace hardware
}  // namespace android
#endif // HIDL_GENERATED_ANDROID_HARDWARE_KEYMASTER_V3_0_AKEYMASTERDEVICE_H
