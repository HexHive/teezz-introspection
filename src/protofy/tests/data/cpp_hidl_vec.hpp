#include <hardware/keymaster2.h>

#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>
#include <hidl/Status.h>

#include <hidl/MQDescriptor.h>
namespace android {
namespace hardware {
namespace keymaster {
namespace V3_0 {
namespace implementation {

using ::android::hardware::hidl_vec;
using ::android::hardware::hidl_string;

class TestClass {
  public:
    TestClass() {}
    virtual ~TestClass();
    void test_method(const hidl_vec<hidl_string> no_lvalue_ref);
    void lvalue_test_method(const hidl_vec<hidl_string> &lvalue_ref);
  private:
    hidl_vec<hidl_string> my_string;
};
}
}
}
}
}
