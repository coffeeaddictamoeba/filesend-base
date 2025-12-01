CXX       := g++
CXXFLAGS  := -std=c++17 -Wall -Wextra -O2 -Iinclude
CFLAGS    := -Wall -Wextra -O2 -Iinclude
LDFLAGS   := -lsodium -lcurl -lssl -lcrypto -lpthread

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