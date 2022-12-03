#!/bin/sh

#VER=14.312.139
#NEWVER=0x0e01388c
VER=14.502.139
NEWVER=0x0e01f68c

arm-none-eabi-gcc \
	-W -Wall -Wextra -Wconversion \
	-Os \
	-ffunction-sections \
	-nostartfiles -nodefaultlibs \
	-mcpu=cortex-m4 -mthumb -mpure-code \
	-o fixed.elf fixed.c -Wl,-Tlink.$VER.ld || exit

arm-none-eabi-objdump fixed.elf -D \
	-j .KaosScheduleWaitingTask \
	-j .KaosScheduleTimer

#arm-none-eabi-objcopy fixed.elf \
#	--dump-section .KaosScheduleWaitingTask=KaosScheduleWaitingTask.bin \
#	--dump-section .KaosScheduleTimer=KaosScheduleTimer.bin

../makepatch.py ../../samfw/SP7/SurfaceSAM_$VER.bin.[01].img fixed.elf $NEWVER > SP7bugfix.$VER.patch

rm fixed.elf

