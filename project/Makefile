#######################################################################################
.PHONY: help fpga lzw-test lzw-cosim clean
help:
	@echo "Makefile Usage:"
	@echo ""
	@echo "  make all"
	@echo "      Command to build client, encoder and decoder."
	@echo ""
	@echo "  make client"
	@echo "      Command to build client."
	@echo ""
	@echo "  make client_mac"
	@echo "      Command to build client on macOS from the shared client source."
	@echo ""
	@echo "  make encoder "
	@echo "      Command to build encoder."
	@echo "      Run ./encoder -x lzw.xclbin [output_file] for FPGA LZW."
	@echo ""
	@echo "  make lzw-test / make lzw-cosim"
	@echo "      Run the native kernel tests / native tests followed by synthesis and RTL co-simulation."
	@echo ""
	@echo "  make fpga / make package/sd_card.img"
	@echo "      Build the Ultra96 host and kernel / package the board image."
	@echo ""
	@echo "  make decoder "
	@echo "      Command to build decoder."
	@echo ""
	@echo "  make clean "
	@echo "      Command to remove the generated files."
	@echo ""
#######################################################################################

# compiler tools

HOST_CXX ?= aarch64-linux-gnu-g++
VPP ?= ${XILINX_VITIS}/bin/v++
RM = rm -f
RMDIR = rm -rf

VITIS_PLATFORM = u96v2_sbc_base
VITIS_PLATFORM_DIR = ${PLATFORM_REPO_PATHS}
VITIS_PLATFORM_PATH = $(VITIS_PLATFORM_DIR)/u96v2_sbc_base.xpfm

# host compiler global settings
CXXFLAGS += -march=armv8-a+simd -mtune=cortex-a53 -std=c++11 -DVITIS_PLATFORM=$(VITIS_PLATFORM) -D__USE_XOPEN2K8 -I$(XILINX_VIVADO)/include/ -I$(VITIS_PLATFORM_DIR)/sw/$(VITIS_PLATFORM)/linux_domain/sysroot/cortexa72-cortexa53-xilinx-linux/usr/include/xrt/ -O3 -g -Wall -c -fmessage-length=0 --sysroot=$(VITIS_PLATFORM_DIR)/sw/$(VITIS_PLATFORM)/linux_domain/sysroot/cortexa72-cortexa53-xilinx-linux
LDFLAGS += -lxilinxopencl -lpthread -lrt -ldl -lcrypt -lstdc++ -L$(VITIS_PLATFORM_DIR)/sw/$(VITIS_PLATFORM)/linux_domain/sysroot/cortexa72-cortexa53-xilinx-linux/usr/lib/ --sysroot=$(VITIS_PLATFORM_DIR)/sw/$(VITIS_PLATFORM)/linux_domain/sysroot/cortexa72-cortexa53-xilinx-linux

# hardware compiler shared settings
VPP_OPTS = --target hw --platform $(VITIS_PLATFORM_PATH)

#
# LZW hardware and simulation
#
LZW_DIR = fpga/hls
LZW_BUILD = build/lzw
PLATFORM_LINUX = $(VITIS_PLATFORM_DIR)/sw/$(VITIS_PLATFORM)/linux_domain

#
# host files
#
CLIENT_SOURCES = Client/client.cpp
CLIENT_EXE = client
# Avoid a name collision with the Client directory on macOS.
CLIENT_EXE_MAC = client_mac

SERVER_SOURCES = Server/encoder.cpp Server/server.cpp
SERVER_OBJECTS =$(SERVER_SOURCES:.cpp=.o)
SERVER_EXE = encoder

DECODER_SOURCES = Decoder/Decoder.cpp
DECODER_OBJECTS =$(DECODER_SOURCES:.cpp=.o)
DECODER_EXE = decoder

all: $(CLIENT_EXE) $(SERVER_EXE) $(DECODER_EXE)

$(CLIENT_EXE) $(CLIENT_EXE_MAC): $(CLIENT_SOURCES)
	g++ -O3 $(CLIENT_SOURCES) -o "$@"

$(SERVER_EXE): $(SERVER_OBJECTS)
	$(HOST_CXX) -o "$@" $(+) $(LDFLAGS)

Server/encoder.o: $(LZW_DIR)/lzw_kernel.h

$(DECODER_EXE): $(DECODER_OBJECTS)
	$(HOST_CXX) -o "$@" $(+) $(LDFLAGS)

.cpp.o:
	$(HOST_CXX) $(CXXFLAGS) -I./server -o "$@" "$<"

#
# primary build targets
#

.NOTPARALLEL: clean

clean:
	-$(RM) $(SERVER_EXE) $(SERVER_OBJECTS) $(DECODER_EXE) $(DECODER_OBJECTS) $(CLIENT_EXE) $(CLIENT_EXE_MAC)
	-$(RM) lzw.xclbin
	-$(RMDIR) $(LZW_BUILD)

$(LZW_BUILD):
	mkdir -p $@

$(LZW_BUILD)/lzw_seed23.bin: | $(LZW_BUILD)
	python3 -c 'import random; from pathlib import Path; r = random.Random(23); Path("$@").write_bytes(bytes(r.getrandbits(8) for _ in range(8192)))'

$(LZW_BUILD)/lzw_test: $(LZW_DIR)/lzw_kernel.cpp $(LZW_DIR)/lzw_kernel_tb.cpp $(LZW_DIR)/lzw_kernel.h | $(LZW_BUILD)
	$(CXX) -std=c++11 -O2 $(filter %.cpp,$^) -o $@

lzw-test: $(LZW_BUILD)/lzw_test $(LZW_BUILD)/lzw_seed23.bin
	cd $(LZW_BUILD) && ./lzw_test

lzw-cosim: lzw-test
	LZW_SIM_DIR="$(abspath $(LZW_BUILD))" vitis_hls -f $(LZW_DIR)/lzw_sim.tcl

fpga: $(SERVER_EXE) lzw.xclbin

$(LZW_BUILD)/lzw_kernel.xo: $(LZW_DIR)/lzw_kernel.cpp $(LZW_DIR)/lzw_kernel.h | $(LZW_BUILD)
	$(VPP) $(VPP_OPTS) -c -k lzw_kernel -o $@ $<

lzw.xclbin: $(LZW_BUILD)/lzw_kernel.xo
	$(VPP) $(VPP_OPTS) -l -o $@ $<

package/sd_card.img: $(SERVER_EXE) $(DECODER_EXE) lzw.xclbin
	$(VPP) $(VPP_OPTS) --package lzw.xclbin --package.out_dir package \
		--package.kernel_image $(PLATFORM_LINUX)/image/Image \
		--package.dtb $(PLATFORM_LINUX)/image/system.dtb \
		--package.rootfs $(PLATFORM_LINUX)/rootfs/rootfs.ext4 \
		--package.sd_file $(SERVER_EXE) --package.sd_file $(DECODER_EXE) \
		--package.sd_file lzw.xclbin
