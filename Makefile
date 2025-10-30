# Root Makefile for NTCLKS Project

# Default target
all: kernel userspace

# Create build directory
build_dir:
	mkdir -p build

# Build kernel module
kernel: build_dir
	# Build kernel module, artifacts will temporarily appear in src/kernel/
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/src/kernel modules
	# Copy the final .ko file to build directory
	cp src/kernel/ntcore.ko build/
	# Thoroughly clean up ALL build artifacts from the source directory
	rm -f src/kernel/*.o src/kernel/*.ko src/kernel/*.mod* src/kernel/.*.cmd src/kernel/Module.symvers src/kernel/modules.order src/kernel/.module-common.o

# Build userspace components
userspace: build_dir
	gcc -c src/userspace/ntdll_shim.c -o build/ntdll_shim.o -I./src/include
	gcc -o build/ntuserd src/userspace/ntuserd.c -I./src/include
	gcc -o build/memory_test tools/test/memory_test.c build/ntdll_shim.o -I./src/include -I./src/userspace
	gcc -o build/simple_ioctl_test tools/test/simple_ioctl_test.c -I./src/include
	gcc -o build/safe_memory_test tools/test/safe_memory_test.c build/ntdll_shim.o -I./src/include -I./src/userspace
	gcc -o build/comprehensive_memory_test tools/test/comprehensive_memory_test.c build/ntdll_shim.o -I./src/include -I./src/userspace
	gcc -o build/object_test tools/test/object_test.c build/ntdll_shim.o -I./src/include -I./src/userspace

# Clean all builds
clean:
	-sudo rm -rf build
	-$(MAKE) -C src/kernel clean
	rm -rf build

# Install kernel module
install: kernel
	sudo insmod build/ntcore.ko

# Uninstall kernel module
uninstall:
	sudo rmmod ntcore

# Check if required tools are available
check-dependencies:
	@echo "Checking for required tools..."
	@which gcc > /dev/null || (echo "Error: gcc not found"; exit 1)
	@which make > /dev/null || (echo "Error: make not found"; exit 1)
	@if [ ! -d "/lib/modules/$(shell uname -r)/build" ]; then echo "Error: kernel headers not found"; exit 1; fi
	@echo "All dependencies found!"

.PHONY: all kernel userspace clean install uninstall check-dependencies build_dir