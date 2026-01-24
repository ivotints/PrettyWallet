CXX = g++
CXXFLAGS = -Ofast -flto -funroll-loops -pthread -std=c++20
SRC = src/main.cpp src/vanity.cpp src/heuristic.cpp src/keccak.cpp
TARGET_DIR = build/
TARGET_NAME = PrettyWalletGenerator
TARGET = $(TARGET_DIR)$(TARGET_NAME)

# Auto-detect OS
ifeq ($(OS),Windows_NT)
	# Windows (MSYS2/MinGW)
	CXXFLAGS += -DSECP256K1_STATIC
	DEPS_DIR = ./deps/windows
	INCLUDES = -I$(DEPS_DIR) -Iinclude
	STATIC_LIB = $(DEPS_DIR)/libsecp256k1.a
	LDFLAGS = -static -pthread
	CLEAN_TARGET = $(TARGET).exe
else
	# Linux
	DEPS_DIR = ./deps/linux
	INCLUDES = -I$(DEPS_DIR) -Iinclude
	STATIC_LIB = $(DEPS_DIR)/libsecp256k1.a
	CXXFLAGS += -mavx -mavx2
	LDFLAGS =  -pthread -static
	CLEAN_TARGET = $(TARGET)
endif

all: $(TARGET)

$(TARGET): $(SRC)
	mkdir -p $(TARGET_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SRC) $(STATIC_LIB) $(LDFLAGS) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(CLEAN_TARGET)

re: clean all

.PHONY: run clean re
