CXX=g++

CXXFLAGS=-std=c++17 -fsanitize=address,leak -Wall -Wextra

TARGET=kry

SRCS=kry.cpp

OBJS=$(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

clean:
	$(RM) $(OBJS) $(TARGET)

zip:
	zip -r xsmata03.zip $(SRCS) Makefile README.md