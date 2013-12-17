CC=cc
CPPFLAGS=-Wall -g
INC=-I./include -I.
LIB=-L./lib -L.
DEPS=-lpcap

SOURCE = $(wildcard *.cc *.cpp)
OBJECTS := $(patsubst %.cc, %.cpp, $(SOURCE))
OBJECTS := $(patsubst %.cpp, %.o, $(OBJECTS))

main:$(OBJECTS)
	g++ $(INC) $(LIB) $(DEPS) $(CPPFLAGS) -o main $(OBJECTS)
$(OBJECTS):$(SOURCE)
	g++ $(CPPFLAGS) $(INC) -c $(SOURCE)

clean:
	rm -rf *.o *.so main test
