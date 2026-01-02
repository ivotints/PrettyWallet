CXX = g++
CXXFLAGS = -Ofast -mavx2
LDFLAGS = -lsecp256k1
TARGET = PrettyWalletGenerator
SRC = main.cpp

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) $(LDFLAGS) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: run clean
