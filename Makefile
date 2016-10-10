VERSION = 1.0
BUILD_DIR =  ./build/$(VERSION)

.PHONY: build clean

all: clean  build

build:
	go build -o $(BUILD_DIR)/main
	cp config.json $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
