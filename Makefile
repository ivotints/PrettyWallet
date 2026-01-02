CXX = g++
CXXFLAGS = -Ofast -march=native -flto -funroll-loops -pthread
LDFLAGS = -lsecp256k1 -pthread
TARGET = PrettyWalletGenerator
SRC = main.cpp vanity.cpp

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) $(LDFLAGS) -o $(TARGET)

# Add Windows cross-compilation target
CXX_WIN = g++
CXXFLAGS_WIN = -Ofast -flto -funroll-loops -pthread
LDFLAGS_WIN = -lsecp256k1 -pthread -static
TARGET_WIN = bin/PrettyWalletGenerator.exe

windows: $(SRC)
	mkdir -p bin
	$(CXX_WIN) $(CXXFLAGS_WIN) $(SRC) $(LDFLAGS_WIN) -o $(TARGET_WIN)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET) $(TARGET_WIN)

.PHONY: run clean windows
