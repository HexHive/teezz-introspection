#ifndef HIDL_GENERATED_ANDROID_HARDWARE_GATEKEEPER_V1_0_IGATEKEEPER_H
#define HIDL_GENERATED_ANDROID_HARDWARE_GATEKEEPER_V1_0_IGATEKEEPER_H

#include <android/hardware/gatekeeper/1.0/types.h>
#include <android/hidl/base/1.0/IBase.h>

#include <android/hidl/manager/1.0/IServiceNotification.h>

#include <hidl/HidlSupport.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>
#include <utils/NativeHandle.h>
#include <utils/misc.h>

namespace android {
namespace hardware {
namespace gatekeeper {
namespace V1_0 {

struct IGatekeeper : public ::android::hidl::base::V1_0::IBase {
    typedef android::hardware::details::i_tag _hidl_tag;

    // Forward declaration for forward reference support:

    virtual bool isRemote() const override { return false; }


    using enroll_cb = std::function<void(const ::android::hardware::gatekeeper::V1_0::GatekeeperResponse& response)>;
    /**
     * Enrolls desiredPassword, which may be derived from a user selected pin
     * or password, with the private key used only for enrolling authentication
     * factor data.
     * 
     * If there was already a password enrolled, current password handle must be
     * passed in currentPasswordHandle, and current password must be passed in
     * currentPassword. Valid currentPassword must verify() against
     * currentPasswordHandle.
     * 
     * @param uid The Android user identifier
     * 
     * @param currentPasswordHandle The currently enrolled password handle the user
     *    wants to replace. May be empty only if there's no currently enrolled
     *    password. Otherwise must be non-empty.
     * 
     * @param currentPassword The user's current password in plain text.
     *    it MUST verify against current_password_handle if the latter is not-empty
     * 
     * @param desiredPassword The new password the user wishes to enroll in
     *    plaintext.
     * 
     * @return response
     *    On success, data buffer must contain the new password handle referencing
     *    the password provided in desiredPassword.
     *    This buffer can be used on subsequent calls to enroll or
     *    verify. On error, this buffer must be empty.
     *    response.code must always contain operation completion status.
     *    This method may return ERROR_GENERAL_FAILURE or ERROR_RETRY_TIMEOUT on
     *    failure. It must return STATUS_OK on success.
     *    If ERROR_RETRY_TIMEOUT is returned, response.timeout must be non-zero.
     */
    virtual ::android::hardware::Return<void> enroll(uint32_t uid, const ::android::hardware::hidl_vec<uint8_t>& currentPasswordHandle, const ::android::hardware::hidl_vec<uint8_t>& currentPassword, const ::android::hardware::hidl_vec<uint8_t>& desiredPassword, enroll_cb _hidl_cb) = 0;

    using verify_cb = std::function<void(const ::android::hardware::gatekeeper::V1_0::GatekeeperResponse& response)>;
    /**
     * Verifies that providedPassword matches enrolledPasswordHandle.
     * 
     * Implementations of this module may retain the result of this call
     * to attest to the recency of authentication.
     * 
     * On success, returns verification token in response.data, which shall be
     * usable to attest password verification to other trusted services.
     * 
     * @param uid The Android user identifier
     * 
     * @param challenge An optional challenge to authenticate against, or 0.
     *    Used when a separate authenticator requests password verification,
     *    or for transactional password authentication.
     * 
     * @param enrolledPasswordHandle The currently enrolled password handle that
     *    user wishes to verify against. Must be non-empty.
     * 
     * @param providedPassword The plaintext password to be verified against the
     *    enrolledPasswordHandle
     * 
     * @return response
     *    On success, a non-empty data buffer containing the
     *    authentication token resulting from this verification is returned.
     *    On error, data buffer must be empty.
     *    response.code must always contain operation completion status.
     *    This method may return ERROR_GENERAL_FAILURE or ERROR_RETRY_TIMEOUT on
     *    failure. It must return STATUS_OK on success.
     *    If password re-enrollment is necessary, it must return STATUS_REENROLL.
     *    If ERROR_RETRY_TIMEOUT is returned, response.timeout must be non-zero.
     */
    virtual ::android::hardware::Return<void> verify(uint32_t uid, uint64_t challenge, const ::android::hardware::hidl_vec<uint8_t>& enrolledPasswordHandle, const ::android::hardware::hidl_vec<uint8_t>& providedPassword, verify_cb _hidl_cb) = 0;

    using deleteUser_cb = std::function<void(const ::android::hardware::gatekeeper::V1_0::GatekeeperResponse& response)>;
    /**
     * Deletes the enrolledPasswordHandle associated with the uid. Once deleted
     * the user cannot be verified anymore.
     * This is an optional method.
     * 
     * @param uid The Android user identifier
     * 
     * @return response
     *    response.code must always contain operation completion status.
     *    This method may return ERROR_GENERAL_FAILURE or ERROR_RETRY_TIMEOUT on
     *    failure. It must return STATUS_OK on success.
     *    If not implemented, it must return ERROR_NOT_IMPLEMENTED.
     *    If ERROR_RETRY_TIMEOUT is returned, response.timeout must be non-zero.
     */
    virtual ::android::hardware::Return<void> deleteUser(uint32_t uid, deleteUser_cb _hidl_cb) = 0;

    using deleteAllUsers_cb = std::function<void(const ::android::hardware::gatekeeper::V1_0::GatekeeperResponse& response)>;
    /**
     * Deletes all the enrolled_password_handles for all uid's. Once called,
     * no users must be enrolled on the device.
     * This is an optional method.
     * 
     * @return response
     *    response.code must always contain operation completion status.
     *    This method may return ERROR_GENERAL_FAILURE or ERROR_RETRY_TIMEOUT on
     *    failure. It must return STATUS_OK on success.
     *    If not implemented, it must return ERROR_NOT_IMPLEMENTED.
     *    If ERROR_RETRY_TIMEOUT is returned, response.timeout must be non-zero.
     */
    virtual ::android::hardware::Return<void> deleteAllUsers(deleteAllUsers_cb _hidl_cb) = 0;

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
    static ::android::hardware::Return<::android::sp<::android::hardware::gatekeeper::V1_0::IGatekeeper>> castFrom(const ::android::sp<::android::hardware::gatekeeper::V1_0::IGatekeeper>& parent, bool emitError = false);
    static ::android::hardware::Return<::android::sp<::android::hardware::gatekeeper::V1_0::IGatekeeper>> castFrom(const ::android::sp<::android::hidl::base::V1_0::IBase>& parent, bool emitError = false);

    static const char* descriptor;

    static ::android::sp<IGatekeeper> tryGetService(const std::string &serviceName="default", bool getStub=false);
    static ::android::sp<IGatekeeper> tryGetService(const char serviceName[], bool getStub=false)  { std::string str(serviceName ? serviceName : "");      return tryGetService(str, getStub); }
    static ::android::sp<IGatekeeper> tryGetService(const ::android::hardware::hidl_string& serviceName, bool getStub=false)  { std::string str(serviceName.c_str());      return tryGetService(str, getStub); }
    static ::android::sp<IGatekeeper> tryGetService(bool getStub) { return tryGetService("default", getStub); }
    static ::android::sp<IGatekeeper> getService(const std::string &serviceName="default", bool getStub=false);
    static ::android::sp<IGatekeeper> getService(const char serviceName[], bool getStub=false)  { std::string str(serviceName ? serviceName : "");      return getService(str, getStub); }
    static ::android::sp<IGatekeeper> getService(const ::android::hardware::hidl_string& serviceName, bool getStub=false)  { std::string str(serviceName.c_str());      return getService(str, getStub); }
    static ::android::sp<IGatekeeper> getService(bool getStub) { return getService("default", getStub); }
    __attribute__ ((warn_unused_result))::android::status_t registerAsService(const std::string &serviceName="default");
    static bool registerForNotifications(
            const std::string &serviceName,
            const ::android::sp<::android::hidl::manager::V1_0::IServiceNotification> &notification);
};

static inline std::string toString(const ::android::sp<::android::hardware::gatekeeper::V1_0::IGatekeeper>& o) {
    std::string os = "[class or subclass of ";
    os += ::android::hardware::gatekeeper::V1_0::IGatekeeper::descriptor;
    os += "]";
    os += o->isRemote() ? "@remote" : "@local";
    return os;
}


}  // namespace V1_0
}  // namespace gatekeeper
}  // namespace hardware
}  // namespace android

#endif  // HIDL_GENERATED_ANDROID_HARDWARE_GATEKEEPER_V1_0_IGATEKEEPER_H
