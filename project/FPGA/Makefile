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
VPP_OPTS = --target hw


#
# OpenCL kernel files
#
XO := lzw_kernel.xo
XCLBIN := encoder.xclbin

#
# host files (host.cpp is the encoder; server.cpp is the course ethernet server)
#
HOST_SOURCES = ./host.cpp ./xcl2.cpp ./server.cpp
HOST_OBJECTS =$(HOST_SOURCES:.cpp=.o)
HOST_EXE = encoder


.PHONY: all clean lzw-test lzw-cosim

all: package/sd_card.img

.cpp.o:
	$(HOST_CXX) $(CXXFLAGS) -I. -o "$@" "$<"

$(HOST_OBJECTS): xcl2.hpp server.h encoder.h stopwatch.h lzw_kernel.h

$(HOST_EXE): $(HOST_OBJECTS)
	$(HOST_CXX) -o "$@" $(+) $(LDFLAGS)

$(XO): ./lzw_kernel.cpp lzw_kernel.h u96_v2.cfg
	$(VPP) $(VPP_OPTS) -k lzw_kernel --compile -I"$(<D)" --config ./u96_v2.cfg -o"$@" "$<"

$(XCLBIN): $(XO) u96_v2.cfg
	$(VPP) $(VPP_OPTS) --link --config ./u96_v2.cfg -o"$@" $(XO)

package/sd_card.img: $(HOST_EXE) $(XCLBIN) xrt.ini
	$(VPP) --package $(VPP_OPTS) --platform $(VITIS_PLATFORM) $(XCLBIN) \
	       --package.out_dir package \
	       --package.sd_file $(HOST_EXE)\
	       --package.kernel_image $(PLATFORM_REPO_PATHS)/sw/u96v2_sbc_base/linux_domain/image/Image \
	       --package.dtb $(PLATFORM_REPO_PATHS)/sw/u96v2_sbc_base/linux_domain/image/system.dtb \
	       --package.rootfs ${PLATFORM_REPO_PATHS}/sw/u96v2_sbc_base/linux_domain/rootfs/rootfs.ext4 \
	       --package.sd_file $(XCLBIN) \
	       --package.sd_file xrt.ini

#
# LZW kernel tests (moved from the top-level Makefile)
#   make lzw-test  : native C++ testbench (g++), seconds
#   make lzw-cosim : lzw-test, then Vitis HLS synthesis + C/RTL co-simulation (lzw_sim.tcl)
#
LZW_BUILD ?= build/lzw

$(LZW_BUILD):
	mkdir -p $@

$(LZW_BUILD)/lzw_seed23.bin: | $(LZW_BUILD)
	python3 -c 'import random; from pathlib import Path; r = random.Random(23); Path("$@").write_bytes(bytes(r.getrandbits(8) for _ in range(8192)))'

$(LZW_BUILD)/lzw_test: ./lzw_kernel.cpp ./lzw_kernel_tb.cpp lzw_kernel.h | $(LZW_BUILD)
	$(CXX) -std=c++11 -O2 $(filter %.cpp,$^) -o $@

lzw-test: $(LZW_BUILD)/lzw_test $(LZW_BUILD)/lzw_seed23.bin
	cd $(LZW_BUILD) && ./lzw_test

lzw-cosim: lzw-test
	cd $(LZW_BUILD) && LZW_SIM_DIR="$(abspath $(LZW_BUILD))" vitis_hls -f $(abspath lzw_sim.tcl)

clean:
	-$(RM) $(HOST_EXE) *.o *.xo *.xclbin *.xclbin.sh *.xclbin.info *.xclbin.link_summary* *.compile_summary *.str
	-$(RM) *json *csv *log *summary *.json *.jou
	-$(RMDIR) _x
	-$(RMDIR) .Xil
	-$(RMDIR) .ipcache
	-$(RMDIR) package
	-$(RMDIR) build
