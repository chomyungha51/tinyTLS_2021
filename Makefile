TARGET = tinyTLS

LIBS = -lcrypto

STUDENT_ID := 2018312567
CXX = g++
CFLAGS = -Wall -g -DSTUDENT_ID=$(STUDENT_ID)
INCLUDES := -I$(shell pwd)/include
STD := c++14

.PHONY: default all clean lib

default: $(TARGET)

lib:
	$(MAKE) -C ./lib

all: default

OBJECTS = $(patsubst %.cc, %.o, $(wildcard *.cc))
OBJECTS += $(patsubst lib/%.cc, lib/%.o, $(wildcard lib/*.cc))

HEADERS = $(wildcard *.h)

%.o: %.cc $(HEADERS)
		$(CXX)  $(INCLUDES) $(CFLAGS) -std=$(STD) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS) lib
		$(CXX) $(CFLAGS) $(OBJECTS) -std=$(STD) -Wall $(LIBS) -o $@

clean:
		$(MAKE) -C ./lib clean
		-rm -f *.o *.txt *.gdb_history
		-rm -f $(TARGET)
