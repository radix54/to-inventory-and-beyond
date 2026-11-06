.PHONY: run build clean

BIN_DIR		:=bin
APP_NAME	:=app
BIN			:=$(BIN_DIR)/$(APP_NAME)
#LIB_ARCHIVE := $(BIN_DIR)/*

run: build
	@./$(BIN)

build: #lib
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN) ./cmd

#lib: submodule
#	@mkdir -p $(BIN_DIR)
#	go build -buildmode=archive -o $(LIB_ARCHIVE) $(LIB_PKG)

# Development utilities
init: 
	@git config core.hooksPath .githooks

clean:
	@rm -rf $(BIN_DIR)
