CXX = g++
CXXFLAGS = -Ofast -march=native -flto -funroll-loops -pthread
LDFLAGS = -lsecp256k1 -pthread
TARGET = PrettyWalletGenerator
SRC = main.cpp

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) $(LDFLAGS) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: run clean
