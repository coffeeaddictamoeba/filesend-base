CXX := g++

PROFILE ?= FULL

COMMON_CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -Iinclude
COMMON_LDFLAGS_REQ := -lsodium -lssl -lcrypto

ifeq ($(PROFILE),MINIMAL_WS)
  PROFILE_DEFINE := -DFILESEND_PROFILE_MINIMAL_WS
  LDFLAGS := $(COMMON_LDFLAGS_REQ)
else ifeq ($(PROFILE),FULL)
  PROFILE_DEFINE := -DFILESEND_PROFILE_FULL
  LDFLAGS := $(COMMON_LDFLAGS_REQ) -lcurl -lpthread -lzip -larchive
else ifeq ($(PROFILE),MINIMAL_HTTP)
  PROFILE_DEFINE := -DFILESEND_PROFILE_MINIMAL_HTTP
  LDFLAGS := $(COMMON_LDFLAGS_REQ) -lcurl
else ifeq ($(PROFILE),CUSTOM)
  PROFILE_DEFINE := -DFILESEND_PROFILE_CUSTOM
  LDFLAGS := $(COMMON_LDFLAGS_REQ) -lcurl -lpthread -lzip -larchive # choose the ones you selected. For HTTP support you need -lcurl; MT - -lpthread; batching - -lzip -larchive
else
  $(error Unsupported PROFILE='$(PROFILE)'. Use PROFILE=FULL, PROFILE=CUSTOM, PROFILE=MINIMAL_HTTP or PROFILE=MINIMAL_WS)
endif

CXXFLAGS := $(COMMON_CXXFLAGS) $(PROFILE_DEFINE)

SRC_DIR   := src
OBJ_DIR   := obj
BUILD_DIR := bin


CPP_SOURCES := $(wildcard $(SRC_DIR)/*.cpp)
CPP_OBJECTS := $(CPP_SOURCES:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)
OBJECTS     := $(CPP_OBJECTS)

EXECUTABLE  := $(BUILD_DIR)/filesend

all: $(EXECUTABLE)

$(BUILD_DIR):
	mkdir -p $@

$(OBJ_DIR):
	mkdir -p $@

$(EXECUTABLE): $(OBJECTS) | $(BUILD_DIR)
	$(CXX) $^ -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(BUILD_DIR)

print-config:
	@echo "PROFILE=$(PROFILE)"
	@echo "CXXFLAGS=$(CXXFLAGS)"
	@echo "LDFLAGS=$(LDFLAGS)"

.PHONY: all clean print-config