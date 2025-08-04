# Makefile for eBPF-sentinel

# Define variables for easy modification
CC = clang
CFLAGS = -O2 -g -target bpf
INCLUDES = -I /usr/include/x86_64-linux-gnu
SOURCE = eBPF-sentinel.c
OBJECT = eBPF-sentinel.o

OPENWRT_BIN = openwrt-main

# The default target. This is what 'make' will build.
all: $(OBJECT)

# Rule to compile the object file from the source file
$(OBJECT): $(SOURCE)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Build the Go static binary for Linux AMD64
openwrt:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(OPENWRT_BIN) main.go

# Clean up build artifacts
clean:
	rm -f $(OBJECT) openwrt_ebpf_static

