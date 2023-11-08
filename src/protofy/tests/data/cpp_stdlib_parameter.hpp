#include <string>
#include <vector>

class MyClass {
  public:
    MyClass();
    ~MyClass();
    void myfunc_a(std::string string_a);
    void myfunc_b(std::string &string_a);
    void myfunc_c(std::vector<int> vec_a);
    void myfunc_d(std::vector<long> &vec_a);
  private:
    std::string i1;
    std::vector<int> i2;
    std::vector<long> i3;
};
