namespace foo {
namespace bar {
namespace baz {

class MyHAL {
  public:
    MyHAL();
    ~MyHAL();
    void myfunc(int a, int b);

    struct InnerStruct1{
	int myfuncinner1(int a, int b);

	struct InnerStruct2{
	    int inner_var;
	    int myfuncinner2(int a, int b);
	};
    };
};

} // namespace foo
} // namespace bar
} // namespace baz
