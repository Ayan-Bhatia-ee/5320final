# Run with make lzw-cosim from project/FPGA (the recipe cds into the build directory).
set build_dir $::env(LZW_SIM_DIR)
set src_dir [file dirname [file normalize [info script]]]
# Run from inside $build_dir (the Makefile cds there) so HLS resolves its relative
# source paths from the same directory it saved them against.
open_project -reset hls
set_top lzw_kernel
add_files [file join $src_dir lzw_kernel.cpp]
add_files -tb [file join $src_dir lzw_kernel_tb.cpp] -cflags "-std=c++11"
add_files -tb [file join $build_dir lzw_seed23.bin]
open_solution -reset solution -flow_target vitis
set_part xczu3eg-sbva484-1-i
create_clock -period 10
# make lzw-cosim already ran this testbench against the C++ kernel.
csynth_design
cosim_design
exit
