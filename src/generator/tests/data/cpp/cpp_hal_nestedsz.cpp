#include <iostream>
#include "cpp_hal_nestedsz.hpp"

int MyHAL::func_a(const std::vector<KeyParameter> &v)
{
    std::cout << "sz of v is " << sizeof(v) << std::endl;
    return 0;
}

int main()
{
    MyHAL m;

    struct KeyParameter p1;
    struct KeyParameter p2;

    p1.tag = 0xaaaaaaaa;
    p1.f.algorithm = 0xdeadbeef;
    // we do not init p1.blob intentionally for p1

    p2.tag = 0xbbbbbbbb;
    // we do not init p2.f intentionally for p2
    for (char c = 0x41; c < 0x61; c++)
    {
        p2.blob.push_back(c);
    }
    std::vector<KeyParameter> v{p1, p2};

    m.func_a(v);

    std::cout << "Finished testcase" << std::endl;
    return 0;
}
