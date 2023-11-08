
main: main.cpp
	clang $< -o $@ -I/usr/lib/llvm-12/include -lclang


run: main
	./main

clean:
	$(RM) ./main
