CXX = g++
CXXFLAGS = -Ofast -flto -funroll-loops -pthread -std=c++23
ARCH = $(shell uname -m)

SRC = $(wildcard src/*.cpp)
OBJ_DIR = build/obj
TARGET_DIR = build
TARGET_NAME = PrettyWalletGenerator
TARGET = $(TARGET_DIR)/$(TARGET_NAME)
OBJS = $(patsubst src/%.cpp, $(OBJ_DIR)/%.o, $(SRC))

EXTERNAL_DIR = ./external

SECP256K1_DIR = $(EXTERNAL_DIR)/secp256k1
SECP256K1_LIB = $(SECP256K1_DIR)/.libs/libsecp256k1.a

SODIUM_DIR = $(EXTERNAL_DIR)/libsodium
SODIUM_LIB = $(SODIUM_DIR)/src/libsodium/.libs/libsodium.a

INCLUDES = -I$(SECP256K1_DIR)/include -I$(SODIUM_DIR)/src/libsodium/include -Iinclude
LDFLAGS = -pthread

ifeq ($(ARCH),x86_64)
	CXXFLAGS += -mavx -mavx2
endif

all: $(TARGET)

$(SECP256K1_LIB):
	@if [ ! -f $(SECP256K1_DIR)/autogen.sh ]; then \
		echo "Submodules missing, initializing..."; \
		git submodule update --init --remote; \
	fi
	@echo "Building secp256k1..."
	cd $(SECP256K1_DIR) && ./autogen.sh
	cd $(SECP256K1_DIR) && ./configure --enable-static --disable-shared --disable-tests --disable-benchmark
	$(MAKE) -C $(SECP256K1_DIR)
	@echo "secp256k1 built."

$(SODIUM_LIB):
	@if [ ! -f $(SODIUM_DIR)/autogen.sh ]; then \
		echo "Submodules missing, initializing..."; \
		git submodule update --init --remote; \
	fi
	@echo "Building libsodium..."
	cd $(SODIUM_DIR) && autoreconf -fi
	cd $(SODIUM_DIR) && ./configure --enable-static --disable-shared
	$(MAKE) -C $(SODIUM_DIR)
	@echo "libsodium built."

$(OBJ_DIR)/%.o: src/%.cpp
	@mkdir -p $(OBJ_DIR)
	@echo "Compiling $<..."
	@$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(TARGET): $(SECP256K1_LIB) $(SODIUM_LIB) $(OBJS)
	@mkdir -p $(TARGET_DIR)
	@echo "Linking $(TARGET)..."
	@$(CXX) $(CXXFLAGS) $(OBJS) $(SECP256K1_LIB) $(SODIUM_LIB) $(LDFLAGS) -o $(TARGET)
	@echo "Done."

run: $(TARGET)
	./$(TARGET)

# build and execute under perf profiler
profile: $(TARGET)
	@echo "Running $(TARGET) with perf profiler..."
	perf record -g -- ./$(TARGET)
# perf report       - to see results

clean:
	rm -rf $(TARGET_DIR)

fclean: clean
	$(MAKE) -C $(SECP256K1_DIR) distclean
	$(MAKE) -C $(SODIUM_DIR) distclean

re: clean all

.PHONY: run clean fclean re