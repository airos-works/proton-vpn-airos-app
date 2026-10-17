# Native Haiku build with the development tools bundled with Haiku; the core
# (src/core, no Haiku API) also builds and tests on Linux:
#   make BUILD=build-host check-host
.DEFAULT_GOAL := all
CXX ?= g++
CC ?= gcc
BUILD ?= build-haiku
APP = ProtonVPN
CPPFLAGS += -Isrc -Ithird_party
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++17 -Wall -Wextra -Wno-multichar -Wno-unused-parameter -Wno-sign-compare
CFLAGS ?= -O2 -g
CORE = $(wildcard src/core/*.cpp)
UI = $(wildcard src/ui/*.cpp) src/main.cpp
WG = $(wildcard src/wg/*.cpp)
CLI = $(wildcard src/cli/*.cpp)
THIRD_PARTY_C = third_party/crypt_blowfish/crypt_blowfish.c
CORE_OBJ = $(CORE:%.cpp=$(BUILD)/%.o) $(THIRD_PARTY_C:%.c=$(BUILD)/%.o)
UI_OBJ = $(UI:%.cpp=$(BUILD)/%.o)
WG_OBJ = $(WG:%.cpp=$(BUILD)/%.o)
CLI_OBJ = $(CLI:%.cpp=$(BUILD)/%.o)
# Set TARGET_OS=Haiku when cross-compiling.
TARGET_OS ?= $(shell uname)
ifeq ($(TARGET_OS),Haiku)
CORE_LIBS = -lcurl -lssl -lcrypto -lnetwork
UI_CPPFLAGS = -I/boot/system/develop/headers/private/interface
else
CPPFLAGS += $(shell pkg-config --cflags libcurl openssl 2>/dev/null)
CORE_LIBS = -lcurl -lssl -lcrypto -lpthread
endif
LIBS = -lbe -ltracker -ltranslation $(CORE_LIBS)
.PHONY: all tools core objects openvpn package clean icon assets check check-host
all: $(BUILD)/$(APP) $(BUILD)/proton-wireguard $(BUILD)/proton-vpn-cli
tools: $(BUILD)/proton-wireguard $(BUILD)/proton-vpn-cli
core: $(CORE_OBJ)
objects: $(CORE_OBJ) $(UI_OBJ)
$(BUILD)/$(APP): $(CORE_OBJ) $(UI_OBJ) resources/ProtonVPN.rdef resources/Assets.rdef resources/proton-vpn.hvif
	$(CXX) -o $@.new $(CORE_OBJ) $(UI_OBJ) $(LIBS) -Wl,--export-dynamic
	rc -o $(BUILD)/$(APP).rsrc resources/ProtonVPN.rdef resources/Assets.rdef
	xres -o $@.new $(BUILD)/$(APP).rsrc
	mimeset -f $@.new
	mv $@.new $@
$(BUILD)/proton-wireguard: $(WG_OBJ) $(CORE_OBJ)
	$(CXX) -o $@ $(WG_OBJ) $(CORE_OBJ) $(CORE_LIBS)
$(BUILD)/proton-vpn-cli: $(CLI_OBJ) $(CORE_OBJ)
	$(CXX) -o $@ $(CLI_OBJ) $(CORE_OBJ) $(CORE_LIBS)
$(BUILD)/%.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(UI_CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@
$(BUILD)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/core_tests: $(CORE_OBJ) $(BUILD)/tests/CoreTests.o
	$(CXX) -o $@ $^ $(CORE_LIBS)
check: $(BUILD)/core_tests
	$(BUILD)/core_tests tests
check-host: check
openvpn:
	sh openvpn/build.sh
package: all
	bash tools/package-haiku.sh
clean:
	rm -rf $(BUILD)
-include $(CORE_OBJ:.o=.d) $(UI_OBJ:.o=.d) $(WG_OBJ:.o=.d) $(CLI_OBJ:.o=.d) $(BUILD)/tests/CoreTests.d
$(BUILD)/wg_interop: $(CORE_OBJ) $(BUILD)/tests/WgInterop.o
	$(CXX) -o $@ $^ $(CORE_LIBS)
icon:
	python3 tools/make-icon.py resources/proton-vpn.hvif
assets:
	python3 tools/render-assets.py
