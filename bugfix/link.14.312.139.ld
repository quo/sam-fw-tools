OUTPUT_FORMAT("elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(_start)

SECTIONS
{
	_start = 0;

	KaosTasks           = 0x20002e60;
	KaosNextWaitingTask = 0x20011d4c;

	KaosTimers          = 0x20003750;
	KaosNextTimer       = 0x20011d54;

	.KaosScheduleWaitingTask 0x839a : SUBALIGN(1) { _s = .; *(.text.KaosScheduleWaitingTask) ASSERT(. <= _s+0xc6, "fn too big"); }
	.KaosScheduleTimer       0x8f4c : SUBALIGN(1) { _s = .; *(.text.KaosScheduleTimer)       ASSERT(. <= _s+0xc8, "fn too big"); }
}
