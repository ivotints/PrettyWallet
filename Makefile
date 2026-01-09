CXX = g++
CXXFLAGS = -Ofast -march=native -flto -funroll-loops -pthread
SRC = main.cpp vanity.cpp

# Auto-detect OS
ifeq ($(OS),Windows_NT)
    # Windows (MSYS2/MinGW)
    CXXFLAGS += -DSECP256K1_STATIC
    DEPS_DIR = ./secp256k1
    INCLUDES = -I$(DEPS_DIR)
    STATIC_LIB = $(DEPS_DIR)/libsecp256k1.a
    LDFLAGS = -static -pthread
    TARGET = PrettyWalletGenerator.exe
else
    # Linux
    INCLUDES =
    STATIC_LIB =
    LDFLAGS = -lsecp256k1 -pthread
    TARGET = PrettyWalletGenerator
endif

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SRC) $(STATIC_LIB) $(LDFLAGS) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f PrettyWalletGenerator PrettyWalletGenerator.exe

re: clean $(TARGET)

.PHONY: run clean re
