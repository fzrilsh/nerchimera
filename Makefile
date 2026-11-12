SHELL := /bin/sh
UNAME_S := $(shell uname -s)

ifeq ($(origin CXX),default)
CXX := c++
endif

ENGINE_DIR   := engine
ENGINE_BUILD := $(ENGINE_DIR)/build
ENGINE_SRC   := $(ENGINE_DIR)/inspector.cpp
ENGINE_HDR   := $(ENGINE_DIR)/inspector.h
ENGINE_OBJ   := $(ENGINE_BUILD)/inspector.o
ENGINE_LIB   := $(ENGINE_BUILD)/libinspector.a

CXXFLAGS ?= -O2
ENGINE_WARN   := -Wall -Wextra -Wpedantic -Werror
ENGINE_HARDEN := -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
ENGINE_FLAGS  := -std=c++17 $(CXXFLAGS) -fPIC -fvisibility=hidden $(ENGINE_WARN) $(ENGINE_HARDEN)

ifeq ($(UNAME_S),Darwin)
SHARED_EXT   := dylib
SHARED_FLAGS := -dynamiclib -install_name @rpath/libinspector.dylib
else
SHARED_EXT   := so
SHARED_FLAGS := -shared -Wl,-soname,libinspector.so
endif
ENGINE_SHARED := $(ENGINE_BUILD)/libinspector.$(SHARED_EXT)

ENGINE_TEST_SRC := $(ENGINE_DIR)/tests/harness.cpp
ENGINE_TEST_BIN := $(ENGINE_BUILD)/harness
ENGINE_SANITIZE := -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all
ifeq ($(UNAME_S),Darwin)
ENGINE_ASAN_OPTIONS := halt_on_error=1
else
ENGINE_ASAN_OPTIONS := halt_on_error=1:detect_leaks=1
endif

PROXY_BIN := proxy/netchimera
LAB_BIN   := target-lab/target-lab

todo = @echo "make $@: not implemented yet (see .kiro/specs/netchimera/tasks.md, $(1))" >&2; exit 1

.PHONY: all engine engine-shared engine-test proxy proxy-test lab ui build dev test \
        simulate bench e2e up down clean

all: build

engine: $(ENGINE_LIB)

$(ENGINE_BUILD):
	mkdir -p $@

$(ENGINE_OBJ): $(ENGINE_SRC) $(ENGINE_HDR) | $(ENGINE_BUILD)
	$(CXX) $(ENGINE_FLAGS) -I$(ENGINE_DIR) -c $(ENGINE_SRC) -o $@

$(ENGINE_LIB): $(ENGINE_OBJ)
	rm -f $@
	$(AR) rcs $@ $(ENGINE_OBJ)

engine-shared: $(ENGINE_SHARED)

$(ENGINE_SHARED): $(ENGINE_OBJ)
	$(CXX) $(SHARED_FLAGS) -o $@ $(ENGINE_OBJ)

engine-test: $(ENGINE_TEST_BIN)
	ASAN_OPTIONS=$(ENGINE_ASAN_OPTIONS) UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(ENGINE_TEST_BIN)

$(ENGINE_TEST_BIN): $(ENGINE_SRC) $(ENGINE_HDR) $(ENGINE_TEST_SRC) | $(ENGINE_BUILD)
	$(CXX) -std=c++17 -O1 -g $(ENGINE_WARN) $(ENGINE_SANITIZE) -pthread -I$(ENGINE_DIR) \
		$(ENGINE_SRC) $(ENGINE_TEST_SRC) -o $@

proxy: $(ENGINE_LIB)
	cd proxy && CGO_ENABLED=1 CGO_CFLAGS="-O2 -g -DNETCHIMERA_ENGINE_STAMP=$$(cksum < ../$(ENGINE_LIB) | cut -d' ' -f1)" \
		go build -trimpath -o netchimera .

proxy-test: $(ENGINE_LIB)
	cd proxy && CGO_ENABLED=1 GODEBUG=cgocheck=1 go vet ./... && CGO_ENABLED=1 GODEBUG=cgocheck=1 go test -race ./...

lab: $(LAB_BIN)

$(LAB_BIN): $(wildcard target-lab/*.go) target-lab/go.mod
	cd target-lab && go build -trimpath -o target-lab .

ui:
	$(call todo,task 14.5)

build:
	$(call todo,task 15.3)

dev:
	$(call todo,task 15.3)

test:
	$(call todo,task 15.3)

simulate:
	@PROXY_URL=$${PROXY_URL:-http://127.0.0.1:8080} ./scripts/simulate.sh

bench:
	$(call todo,task 15.4)

e2e:
	$(call todo,task 15.4)

up:
	$(call todo,task 15.3)

down:
	$(call todo,task 15.3)

clean:
	rm -rf $(ENGINE_BUILD) $(PROXY_BIN) $(LAB_BIN)
