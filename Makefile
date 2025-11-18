CC=gcc
CFLAGS=-Wall -Wextra -O2 -Iinclude 
LDFLAGS=-lsodium
BUILD_DIR = bin
OBJ_DIR = obj
SRC_DIR = src

SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
EXECUTABLE = $(BUILD_DIR)/file_encrypt

all: $(EXECUTABLE)

$(BUILD_DIR):
	mkdir -p $@

$(OBJ_DIR):
	mkdir -p $@

$(EXECUTABLE): $(OBJECTS) | $(BUILD_DIR)
	$(CC) $(LDFLAGS) $^ -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -r $(BUILD_DIR) $(OBJ_DIR)

.PHONY: all clean
