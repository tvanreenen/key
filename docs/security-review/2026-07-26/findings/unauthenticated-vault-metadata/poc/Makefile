SWIFTC ?= swiftc
TARGET := metadata-regression
SOURCE := metadata_regression.swift
MODULE_CACHE := .build/swift-module-cache
CLANG_CACHE := .build/clang-module-cache

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(SOURCE) inconsistent-metadata.json
	mkdir -p $(MODULE_CACHE) $(CLANG_CACHE)
	SWIFT_MODULECACHE_PATH=$(CURDIR)/$(MODULE_CACHE) \
	CLANG_MODULE_CACHE_PATH=$(CURDIR)/$(CLANG_CACHE) \
	$(SWIFTC) $(SOURCE) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -rf $(TARGET) .build
