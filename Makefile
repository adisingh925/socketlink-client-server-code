# Build the Socketlink standalone server from the modular sources in src/.
#
# External dependencies are staged in SL_DEPS (default: $(HOME)/sl-deps):
#   include/{json.hpp,simdjson.h}, simdjson.cpp,
#   uWebSockets/ (with uSockets/uSockets.a built via `WITH_OPENSSL=1 make`)
# plus the apt dev libs: build-essential libssl-dev zlib1g-dev liblmdb-dev
#   libtbb-dev libboost-all-dev libmysqlclient-dev
#
# Usage: make -j$(nproc)           -> build/socketlink        (epoll backend)
#        make -j$(nproc) URING=1   -> build-uring/socketlink  (io_uring backend)
#        make SL_DEPS=/path/to/deps
#
# URING=1 links a uSockets archive built with WITH_IO_URING=1 (expected at
# $(SL_DEPS)/uSockets-uring/uSockets.a) and compiles the app with the same
# LIBUS_USE_IO_URING define — the two must match, hence the separate build dir.
#
# WARNING (2026-08): the uSockets v20.67.0 io_uring backend is an unfinished
# prototype and SEGFAULTS under load (null on_data via use-after-free: multishot
# recv completions arrive after close frees the socket; SOCKET_WRITE completion
# handling is empty). It boots and serves light HTTP but died at 2k conns.
# Kept only for re-testing if upstream ever matures the backend. Use epoll.

SL_DEPS ?= $(HOME)/sl-deps

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2
CXXFLAGS += -MMD -MP
CPPFLAGS += -I$(SL_DEPS)/uWebSockets/src -I$(SL_DEPS)/uWebSockets/uSockets/src \
            -I$(SL_DEPS)/include -I/usr/include/mysql
LDLIBS   += -lssl -lcrypto -lz -llmdb -ltbb -lmysqlclient -lpthread

ifeq ($(URING),1)
BUILD    := build-uring
CPPFLAGS += -DLIBUS_USE_IO_URING
USOCKETS := $(SL_DEPS)/uSockets-uring/uSockets.a
LDLIBS   += -luring
else
BUILD    := build
USOCKETS := $(SL_DEPS)/uWebSockets/uSockets/uSockets.a
endif

SRCS := $(wildcard src/*.cpp)
OBJS := $(SRCS:src/%.cpp=$(BUILD)/%.o) $(BUILD)/simdjson.o

all: $(BUILD)/socketlink

$(BUILD)/socketlink: $(OBJS)
	$(CXX) $(CXXFLAGS) $^ $(USOCKETS) $(LDLIBS) -o $@

$(BUILD)/%.o: src/%.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD)/simdjson.o: $(SL_DEPS)/simdjson.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD):
	mkdir -p $(BUILD)

loadgen: $(BUILD)/loadgen

$(BUILD)/loadgen: tests/loadgen.cpp | $(BUILD)
	$(CXX) -std=c++17 -O2 -pthread $< -o $@

## Unit tests for the pure functions — seconds to run, no server needed.
test: $(BUILD)/unit_tests
	@$(BUILD)/unit_tests

$(BUILD)/unit_tests: tests/unit_tests.cpp src/Util.cpp src/Util.h | $(BUILD)
	$(CXX) -std=c++17 -O2 -g tests/unit_tests.cpp src/Util.cpp -lssl -lcrypto -o $@

clean:
	rm -rf build build-uring

-include $(OBJS:.o=.d)

.PHONY: all clean loadgen test
