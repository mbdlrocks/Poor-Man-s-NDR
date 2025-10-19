LIBTORCH = ./libtorch
CXX := g++
CXXFLAGS := -std=c++17 -O2 -Iincludes -I$(LIBTORCH)/include -I$(LIBTORCH)/include/torch/csrc/api/include
LDFLAGS := -L$(LIBTORCH)/lib -ltorch -ltorch_cpu -lc10 -lpthread -ldl -lm -Wl,-rpath,$(LIBTORCH)/lib
TARGET := flowtracker
SRC := main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	sudo ./$(TARGET)
