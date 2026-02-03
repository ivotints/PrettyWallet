CXX = g++
CXXFLAGS = -Ofast -flto -funroll-loops -pthread -std=c++20
ARCH = $(shell uname -m)
PKGCONFIG ?= pkg-config
SRC = src/main.cpp src/vanity.cpp src/heuristic.cpp src/keccak.cpp
TARGET_DIR = build/
TARGET_NAME = PrettyWalletGenerator
TARGET = $(TARGET_DIR)$(TARGET_NAME)
LIBS =

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
	HAS_SECP := $(shell $(PKGCONFIG) --exists libsecp256k1 && echo 1 || echo 0)
	ifeq ($(HAS_SECP),1)
		INCLUDES = -Iinclude $(shell $(PKGCONFIG) --cflags libsecp256k1)
		LIBS = $(shell $(PKGCONFIG) --libs libsecp256k1)
		STATIC_LIB =
		LDFLAGS = -pthread
	else
		DEPS_DIR = ./deps/linux
		INCLUDES = -I$(DEPS_DIR) -Iinclude
		STATIC_LIB = $(DEPS_DIR)/libsecp256k1.a
		LDFLAGS =  -pthread -static
	endif
	ifeq ($(ARCH),x86_64)
		CXXFLAGS += -mavx -mavx2
	endif
	CLEAN_TARGET = $(TARGET)
endif

all: $(TARGET)

$(TARGET): $(SRC)
	mkdir -p $(TARGET_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SRC) $(STATIC_LIB) $(LIBS) $(LDFLAGS) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(CLEAN_TARGET)

re: clean all

.PHONY: run clean re
