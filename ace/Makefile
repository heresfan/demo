CC = cc
#CPP = g++
CFLAGS = -g -Wall
CPPFLAGS = -g -Wall

LDFLAGS = -L ./lib
INCFLAGS = -I ./include
LIBS = -lACE
OUT = main

SOURCE = $(wildcard *.cc *.cpp)
OBJECTS := $(patsubst %.cc, %.cpp, $(SOURCE))
OBJECTS := $(patsubst %.cpp, %.o, $(OBJECTS))

main:$(OBJECTS)
	$(CC) $(INCFLAGS) $(LDFLAGS) -o $(OUT) $(OBJECTS) $(LIBS)

$(OBJECTS):$(SOURCE)
	$(CC) -c $(SOURCE)

test:
	LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./lib ./main
clean:
	rm -rf *.o
	rm -rf main
