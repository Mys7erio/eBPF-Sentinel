# Makefile for eBPF-sentinel

# Define variables for easy modification
CC = clang
CFLAGS = -O2 -g -target bpf
INCLUDES = -I /usr/include/x86_64-linux-gnu
SOURCE = eBPF-sentinel.c
OBJECT = eBPF-sentinel.o

# The default target. This is what 'make' will build.
all: $(OBJECT)

# Rule to compile the object file from the source file
$(OBJECT): $(SOURCE)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean up build artifacts
clean:
	rm -f $(OBJECT)
