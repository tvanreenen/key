SWIFTC ?= swiftc
TARGET := device-removal-without-rotation
SOURCE := device_removal_without_rotation.swift
MODULE_CACHE := .build/swift-module-cache
CLANG_CACHE := .build/clang-module-cache

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(SOURCE)
	mkdir -p $(MODULE_CACHE) $(CLANG_CACHE)
	SWIFT_MODULECACHE_PATH=$(CURDIR)/$(MODULE_CACHE) \
	CLANG_MODULE_CACHE_PATH=$(CURDIR)/$(CLANG_CACHE) \
	$(SWIFTC) $(SOURCE) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -rf $(TARGET) .build
