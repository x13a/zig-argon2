srcdir ?= ./src

all: test

test:
	zig build test

clean:
	rm -rf ./zig-cache/
