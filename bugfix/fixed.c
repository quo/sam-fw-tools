#include <stdint.h>

typedef uint32_t u32;
typedef uint64_t u64;

struct KaosTask {
	char name[16];
	void *fn;
	char priority;
	u32 isRunning;
	u32 timeout;
	u64 timestamp;
	u32 semaphoreHandle;
	u32 queueHandle;
	void *destBuf;
	u32 eventHandle;
	u32 errorCode;
	u32 mask;
	void *state;
	void *stack;
	u32 stackSize;
	u32 next;
	u32 stats[6];
};
_Static_assert(sizeof(struct KaosTask) == 0x68, "sizeof KaosTask");

struct KaosTimer {
	char name[16];
	void *fn;
	u32 fnArg;
	u64 timestamp;
	u32 timeout;
	char repeating;
	u32 disabled;
	u32 next;
};
_Static_assert(sizeof(struct KaosTimer) == 0x30, "sizeof KaosTimer");

extern u32 KaosNextWaitingTask;
extern struct KaosTask KaosTasks[];

extern u32 KaosNextTimer;
extern struct KaosTimer KaosTimers[];

void KaosScheduleWaitingTask(u32 t) {
	struct KaosTask *tasks = KaosTasks;
	u32 prev = KaosNextWaitingTask;
	if (prev == 0xff) {
		KaosNextWaitingTask = t;
		tasks[t].next = 0xff;
		return;
	}
	// Bugfix: In the official firmware, newWakeTime and wakeTime are u32.
	u64 newWakeTime = tasks[t].timeout == UINT32_MAX ? UINT64_MAX
		: tasks[t].timestamp + tasks[t].timeout;
	u32 i = prev;
	while(1) {
		u64 wakeTime = tasks[i].timeout == UINT32_MAX ? UINT64_MAX
			: tasks[i].timestamp + tasks[i].timeout;
		if (wakeTime >= newWakeTime) {
			tasks[t].next = i;
			if (i == KaosNextWaitingTask) KaosNextWaitingTask = t;
			else tasks[prev].next = t;
			return;
		}
		u32 j = tasks[i].next;
		if (j == 0xff) {
			tasks[i].next = t;
			tasks[t].next = 0xff;
			return;
		}
		prev = i;
		i = j;
	}
}

void KaosScheduleTimer(u32 t) {
	struct KaosTimer *timers = KaosTimers;
	u32 prev = KaosNextTimer;
	if (prev == 0) {
		KaosNextTimer = t;
		timers[t].next = 0;
		return;
	}
	u32 i = prev;
	// Bugfix: In the official firmware, newWakeTime and wakeTime are u32.
	u64 newWakeTime = timers[t].timeout == UINT32_MAX ? UINT64_MAX
		: timers[t].timestamp + timers[t].timeout;
	while(1) {
		u64 wakeTime = timers[i].timeout == UINT32_MAX ? UINT64_MAX
			: timers[i].timestamp + timers[i].timeout;
		if (wakeTime >= newWakeTime) {
			timers[t].next = i;
			if (i == KaosNextTimer) KaosNextTimer = t;
			else timers[prev].next = t;
			return;
		}
		u32 j = timers[i].next;
		if (j == 0) {
			timers[i].next = t;
			timers[t].next = 0;
			return;
		}
		prev = i;
		i = j;
	}
}

