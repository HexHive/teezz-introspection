#include<vector>
#include<string>

struct MyStruct{
    std::vector<int> myfunc_a(int a, int b);
    void myfunc_b(std::vector<int> vec_a, std::vector<int> vec_b);
    void myfunc_c(std::vector<std::string>);
};
