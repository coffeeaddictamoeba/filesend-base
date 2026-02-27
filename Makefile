CXX       := g++
CXXFLAGS  := -std=c++17 -Wall -Wextra -O2 -Iinclude -DFILESEND_PROFILE_FULL

LDFLAGS_REQ := -lsodium -lssl -lcrypto # flags required for all profiles (FULL, CUSTOM, MINIMAL)
LDFLAGS_OPT := -lcurl -lpthread -lzip -larchive # optional flags, comment for MINIMAL

LDFLAGS := $(LDFLAGS_REQ) $(LDFLAGS_OPT)

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

.PHONY: all clean