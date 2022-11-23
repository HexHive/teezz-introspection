CC=gcc
CXX=g++
FRIDA_GADGET_SO=./frida-gadget-14.2.14-linux-x86_64.so

COBJS = $(patsubst %.c,%,$(wildcard c/*.c))
CPPOBJS = $(patsubst %.cpp,%,$(wildcard cpp/*.cpp))

.PHONY: all run clean


all: $(COBJS) $(CPPOBJS)

# run targets with frida gadet preloaded like this:
#run:
#	LD_PRELOAD=$(FRIDA_GADGET_SO) ./main

$(COBJS):%: %.c %.h
	$(CC) -ggdb -o $@.bin $^
	python3 funcsyms2json.py $@.bin | python3 -m json.tool > $@.json

$(CPPOBJS):%: %.cpp %.hpp
	$(CXX) -ggdb -o $@.bin $^
	python3 funcsyms2json.py $@.bin | python3 -m json.tool > $@.json

clean:
	$(RM) c/*.bin c/*.json cpp/*.bin cpp/*.json
