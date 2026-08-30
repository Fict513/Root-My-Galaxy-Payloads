#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    if old not in text:
        if new in text:
            print(f"already applied: {path}")
            return
        raise SystemExit(f"expected source block not found in {path}")
    text = text.replace(old, new, 1)
    p.write_text(text)
    print(f"updated: {path}")


# Target opt-in only. All firmware offsets, P0 data, tracefs gates, MCAST
# constants and KernelSU artifacts remain untouched.
replace_once(
    "src/targets/dm1q-S911BXXSAFZG1/target.h",
    "#if defined(APP_PAYLOAD) && APP_PAYLOAD\n#define SLIDE_MCAST_DOMAIN AF_INET6\n",
    "#if defined(APP_PAYLOAD) && APP_PAYLOAD\n#define APP_SAFE_SPEED_BACKPORT 1\n#define SLIDE_MCAST_DOMAIN AF_INET6\n",
)

replace_once(
    "src/common.h",
    "#define MM_PARTIALS 5\n#define CORE 0\n#ifndef KSNITCH_COLLISIONS\n",
    "#define MM_PARTIALS 5\n#ifndef RMG_CORE_LITERAL\n#define RMG_CORE_LITERAL 0\n#endif\n#define CORE RMG_CORE_LITERAL\nint rmg_resolve_scan_core(void);\n#ifndef KSNITCH_COLLISIONS\n",
)

preload = Path("src/preload.c")
text = preload.read_text()
needle = "static void wait_for_boot_quiet_window(void) {\n#if defined(APP_PAYLOAD) && APP_PAYLOAD\n  struct timespec uptime;\n  SYSCHK(clock_gettime(CLOCK_BOOTTIME, &uptime));\n  if (uptime.tv_sec < APP_MIN_BOOT_UPTIME_SEC) {\n    time_t wait_sec = APP_MIN_BOOT_UPTIME_SEC - uptime.tv_sec;\n    pr_info(\"waiting for boot allocator quiet window seconds=%lld uptime=%lld\\n\",\n            (long long)wait_sec, (long long)uptime.tv_sec);\n    while (wait_sec > 0) {\n      wait_sec = sleep((unsigned int)wait_sec);\n    }\n  }\n#endif\n}\n"
replacement = r'''#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_SAFE_SPEED_BACKPORT) && APP_SAFE_SPEED_BACKPORT
/* Order-3+ free pages across all zones. Once these counts stop changing,
 * the boot allocator storm has settled enough to start without blindly
 * sleeping all the way to 120 seconds. */
static long long buddy_high_order_free(void) {
  FILE *f = fopen("/proc/buddyinfo", "r");
  if (!f) {
    return -1;
  }
  char line[512];
  long long total = -1;
  while (fgets(line, sizeof(line), f)) {
    unsigned long long tokens[24];
    int filled = 0;
    const char *p = line;
    while (*p && filled < 24) {
      char *end = NULL;
      unsigned long long v = strtoull(p, &end, 10);
      if (end == p) {
        p++;
        continue;
      }
      tokens[filled++] = v;
      p = end;
    }
    if (filled >= 11) {
      if (total < 0) {
        total = 0;
      }
      for (int i = filled - 11 + 3; i < filled; ++i) {
        total += (long long)tokens[i];
      }
    }
  }
  fclose(f);
  return total;
}
#endif

static void wait_for_boot_quiet_window(void) {
#if defined(APP_PAYLOAD) && APP_PAYLOAD
  struct timespec uptime;
  SYSCHK(clock_gettime(CLOCK_BOOTTIME, &uptime));
  if (uptime.tv_sec >= APP_MIN_BOOT_UPTIME_SEC) {
    return;
  }
  time_t wait_sec = APP_MIN_BOOT_UPTIME_SEC - uptime.tv_sec;
  pr_info("waiting for boot allocator quiet window seconds=%lld uptime=%lld\n",
          (long long)wait_sec, (long long)uptime.tv_sec);

#if defined(APP_SAFE_SPEED_BACKPORT) && APP_SAFE_SPEED_BACKPORT
  /* Final v1.2.0 policy: 60-second floor, three EXACT identical samples
   * two seconds apart, and the original 120-second hard cap. Intentionally
   * excludes the reverted drift-tolerance experiment that panicked early. */
  static const time_t QUIET_FLOOR_SEC = 60;
  static const int QUIET_STABLE_SAMPLES = 3;
  long long prev = -1;
  int stable = 0;
  struct timespec now_ts;
  for (int poll = 0; poll < 45; ++poll) {
    SYSCHK(clock_gettime(CLOCK_BOOTTIME, &now_ts));
    if (now_ts.tv_sec >= APP_MIN_BOOT_UPTIME_SEC) {
      return;
    }
    if (now_ts.tv_sec >= QUIET_FLOOR_SEC && stable >= QUIET_STABLE_SAMPLES) {
      pr_info("boot allocator quiet (buddy stable) uptime=%lld\n",
              (long long)now_ts.tv_sec);
      return;
    }
    long long now = buddy_high_order_free();
    if (now < 0) {
      break;
    }
    if (prev >= 0 && now == prev) {
      stable++;
    } else {
      stable = 0;
    }
    prev = now;
    sleep(2);
  }
#endif
  while (wait_sec > 0) {
    wait_sec = sleep((unsigned int)wait_sec);
  }
#endif
}
'''
if needle not in text:
    if "buddy_high_order_free" not in text:
        raise SystemExit("expected quiet-window block not found")
else:
    preload.write_text(text.replace(needle, replacement, 1))
    print("updated: src/preload.c")

# Move the env size helper outside the fresh-session guard so the controlled
# mm path can honor the 64/4 profile too, and add a scan-only core resolver.
util = Path("src/util.c")
text = util.read_text()
marker = "static struct kernelsnitch_shared_state *ks;\n"
helper = r'''/* Runtime CPU choice is scan-only. CORE itself stays the proven LITTLE
 * literal, so slide/fops/pi-futex write choreography is unchanged. Perf-core
 * scanning is opt-in until it is validated on dm1q hardware: RMG_SCAN_PERF=1. */
int rmg_resolve_scan_core(void) {
#if defined(APP_SAFE_SPEED_BACKPORT) && APP_SAFE_SPEED_BACKPORT
  const char *enable = getenv("RMG_SCAN_PERF");
  if (!enable || strcmp(enable, "1") != 0) {
    return RMG_CORE_LITERAL;
  }
  cpu_set_t current;
  if (sched_getaffinity(0, sizeof(current), &current) != 0) {
    return RMG_CORE_LITERAL;
  }
  long online = sysconf(_SC_NPROCESSORS_ONLN);
  if (online > AFFINITY_MAX_CPUS) {
    online = AFFINITY_MAX_CPUS;
  }
  for (int c = (int)online - 1; c >= 0; --c) {
    if (!CPU_ISSET(c, &current)) {
      continue;
    }
    cpu_set_t want;
    CPU_ZERO(&want);
    CPU_SET(c, &want);
    if (sched_setaffinity(0, sizeof(want), &want) == 0) {
      sched_setaffinity(0, sizeof(current), &current);
      pr_info("KernelSnitch runtime scan core cpu=%d\n", c);
      return c;
    }
  }
#endif
  return RMG_CORE_LITERAL;
}

static size_t rmg_profile_env_size(const char *name, size_t fallback,
                                   size_t min, size_t max) {
  const char *value = getenv(name);
  if (!value || !*value) {
    return fallback;
  }
  char *end = NULL;
  errno = 0;
  unsigned long long parsed = strtoull(value, &end, 0);
  if (errno || end == value || *end || parsed < min || parsed > max) {
    pr_warning("ignoring invalid %s=%s\n", name, value);
    return fallback;
  }
  return (size_t)parsed;
}

'''
if "int rmg_resolve_scan_core(void)" not in text:
    if marker not in text:
        raise SystemExit("util insertion point missing")
    text = text.replace(marker, helper + marker, 1)

old_helper = r'''static size_t rmg_profile_env_size(const char *name, size_t fallback,
                                   size_t min, size_t max) {
  const char *value = getenv(name);
  if (!value || !*value) {
    return fallback;
  }

  char *end = NULL;
  errno = 0;
  unsigned long long parsed = strtoull(value, &end, 0);
  if (errno || end == value || *end || parsed < min || parsed > max) {
    pr_warning("ignoring invalid %s=%s\n", name, value);
    return fallback;
  }
  return (size_t)parsed;
}

'''
# Remove the original guarded copy; keep the new top-level copy.
pos = text.find(old_helper, text.find(marker))
if pos != -1:
    text = text[:pos] + text[pos + len(old_helper):]

old_profile = "    kernelsnitch_set_profile(state, 256, REPEAT_MEASUREMENT, AVERAGE);\n"
new_profile = r'''    size_t repeat_default = REPEAT_MEASUREMENT;
    size_t average_default = AVERAGE;
#if defined(APP_SAFE_SPEED_BACKPORT) && APP_SAFE_SPEED_BACKPORT
    if (repeat_default > 64) {
      repeat_default = 64;
    }
    if (average_default > 4) {
      average_default = 4;
    }
#endif
    size_t repeat = rmg_profile_env_size(
        "RMG_KSNITCH_REPEAT", repeat_default, 8, REPEAT_MEASUREMENT);
    size_t average = rmg_profile_env_size(
        "RMG_KSNITCH_AVERAGE", average_default, 1, repeat);
    if (average > repeat) {
      average = repeat;
    }
    /* Preserve dm1q's proven controlled-mm pile-up of 256. */
    kernelsnitch_set_profile(state, 256, repeat, average);
'''
if old_profile in text:
    text = text.replace(old_profile, new_profile, 1)
elif "repeat_default = REPEAT_MEASUREMENT" not in text:
    raise SystemExit("controlled_mm_leak profile call not found")
util.write_text(text)
print("updated: src/util.c")

replace_once(
    "src/kernelsnitch/kernelsnitch.h",
    "    pin_to_core(0);\n    futex_init();\n",
    "#if defined(APP_SAFE_SPEED_BACKPORT) && APP_SAFE_SPEED_BACKPORT\n    pin_to_core(rmg_resolve_scan_core());\n#else\n    pin_to_core(0);\n#endif\n    futex_init();\n",
)

ks = Path("src/kernelsnitch/kernelsnitch.h")
text = ks.read_text()
old = "    reset_cpu_pin();\n\n    for (size_t i = 0; i < ks->thread_cnt; ++i) {\n"
new = r'''    reset_cpu_pin();

#if defined(APP_SAFE_SPEED_BACKPORT) && APP_SAFE_SPEED_BACKPORT
    /* Timing-insensitive post-scan boost. Spawned workers inherit the clamp.
     * RMG_UCLAMP=0 disables it immediately for A/B or recovery testing. */
    if (!(getenv("RMG_UCLAMP") && getenv("RMG_UCLAMP")[0] == '0')) {
        struct {
            unsigned int size;
            unsigned int sched_policy;
            unsigned long long sched_flags;
            int sched_nice;
            unsigned int sched_priority;
            unsigned long long sched_runtime;
            unsigned long long sched_deadline;
            unsigned long long sched_period;
            unsigned int sched_util_min;
            unsigned int sched_util_max;
        } attr;
        memset(&attr, 0, sizeof(attr));
        attr.size = (unsigned int)sizeof(attr);
        attr.sched_policy = 0; /* SCHED_NORMAL */
        attr.sched_flags = 0x20; /* SCHED_FLAG_UTIL_CLAMP_MIN */
        attr.sched_util_min = 512;
        attr.sched_util_max = 1024;
        if (syscall(274 /* __NR_sched_setattr */, 0, &attr, 0) == 0) {
            pr_info("ksnitch bruteforce uclamp_min=512\n");
        }
    }
#endif

    for (size_t i = 0; i < ks->thread_cnt; ++i) {
'''
if old in text:
    ks.write_text(text.replace(old, new, 1))
    print("updated: src/kernelsnitch/kernelsnitch.h uclamp")
elif "uclamp_min=512" not in text:
    raise SystemExit("kernelsnitch bruteforce insertion point missing")

slide = Path("src/slide_app.c")
text = slide.read_text()
old = r'''static int slide_child_trigger_write(void) {
  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
'''
new = r'''static int slide_child_trigger_write(void) {
  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  int ready_polls = 0;
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
'''
if old in text:
    text = text.replace(old, new, 1)
elif "int ready_polls = 0;" not in text:
    raise SystemExit("slide write function header not found")
old = r'''  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started) ||
         !atomic_load(&slide_consumer_ready)) {
    usleep(1000);
  }
  if (SLIDE_REQUEUE_ARM_USEC) {
'''
new = r'''  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started) ||
         !atomic_load(&slide_consumer_ready)) {
    usleep(1000);
    if (++ready_polls > 10000) {
      pr_error("slide pi ready-sync timed out\n");
      return 0;
    }
  }
  if (SLIDE_REQUEUE_ARM_USEC) {
'''
# There is an earlier similar loop in slide_child_leak_stext. Limit replacement
# to the write function suffix so only the requested write stage changes.
start = text.index("static int slide_child_trigger_write(void)")
prefix, suffix = text[:start], text[start:]
if old in suffix:
    suffix = suffix.replace(old, new, 1)
elif "slide pi ready-sync timed out" not in suffix:
    raise SystemExit("write ready-sync loop not found")
old = r'''  atomic_store(&slide_deadlock_seen, 1);
  while (!atomic_load(&slide_route_done)) {
    usleep(1000);
  }
#if defined(APP_ACCEPT_SCHED_TRIGGER) && APP_ACCEPT_SCHED_TRIGGER
'''
new = r'''  atomic_store(&slide_deadlock_seen, 1);
  {
    long route_wait_ms = 0;
    while (!atomic_load(&slide_route_done)) {
      usleep(1000);
      if (++route_wait_ms > 20000) {
        pr_error("slide pi route wait timed out after 20s\n");
        return 0;
      }
    }
  }
#if defined(APP_ACCEPT_SCHED_TRIGGER) && APP_ACCEPT_SCHED_TRIGGER
'''
if old in suffix:
    suffix = suffix.replace(old, new, 1)
elif "slide pi route wait timed out after 20s" not in suffix:
    raise SystemExit("write route wait loop not found")
slide.write_text(prefix + suffix)
print("updated: src/slide_app.c")

print("dm1q FZG1 safe speed backport applied")
