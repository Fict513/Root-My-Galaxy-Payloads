#!/usr/bin/env python3
"""Compile the real boot wait with fake OS time; never execute the payload."""
import ast
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def extract_function(source, name):
    start = source.index("static void " + name + "(")
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


HARNESS = r'''
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#define APP_MIN_BOOT_UPTIME_SEC 120
#define SYSCHK(x) do { if ((x) < 0) abort(); } while (0)
#define pr_info(...) do { if (0) printf(__VA_ARGS__); } while (0)
static int64_t now_ns;
static int samples, pattern, interrupt_once, sleep_calls;
static int fake_clock_gettime(clockid_t clock, struct timespec *ts) {
  if (clock != CLOCK_BOOTTIME) abort();
  ts->tv_sec = now_ns / 1000000000LL;
  ts->tv_nsec = now_ns % 1000000000LL;
  return 0;
}
static int fake_nanosleep(const struct timespec *req, struct timespec *rem) {
  (void)rem;
  if (++sleep_calls > 1000 || req->tv_sec < 0 || req->tv_nsec < 0 ||
      req->tv_nsec >= 1000000000L) abort();
  int64_t duration = req->tv_sec * 1000000000LL + req->tv_nsec;
  if (interrupt_once) {
    interrupt_once = 0;
    now_ns += 30250000000LL; /* signal handling/suspend advances BOOTTIME */
    errno = EINTR;
    return -1;
  }
  now_ns += duration;
  return 0;
}
static unsigned int fake_sleep(unsigned int seconds) {
  struct timespec request = {seconds, 0};
  if (fake_nanosleep(&request, NULL) < 0) return seconds;
  return 0;
}
static int fake_clock_nanosleep(clockid_t clock, int flags,
    const struct timespec *deadline, struct timespec *rem) {
  if (clock != CLOCK_BOOTTIME || flags != TIMER_ABSTIME || rem != NULL) abort();
  int64_t remaining = deadline->tv_sec * 1000000000LL + deadline->tv_nsec - now_ns;
  if (remaining <= 0) return 0;
  struct timespec request = {remaining / 1000000000LL, remaining % 1000000000LL};
  return fake_nanosleep(&request, NULL) == 0 ? 0 : errno;
}
static long long buddy_high_order_free(void) {
  samples++;
  if (pattern == 2 || (pattern == 3 && samples > 3)) return -1;
  return pattern == 0 ? 100 : samples;
}
#define clock_gettime fake_clock_gettime
#define nanosleep fake_nanosleep
#define clock_nanosleep fake_clock_nanosleep
#define sleep fake_sleep
'''


class BootQuietWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        script = ast.parse((ROOT / "backports/apply_dm1q_fzg1_speed.py").read_text())
        generated = next(
            ast.literal_eval(node.value) for node in script.body
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "replacement" for t in node.targets)
        )
        sources = {"checked_in": (ROOT / "src/preload.c").read_text(),
                   "generated": generated}
        cls.binaries = {}
        for label, source in sources.items():
            functions = []
            if "static void sleep_until_boot_deadline(" in source:
                functions.append(extract_function(source, "sleep_until_boot_deadline"))
            functions.append(extract_function(source, "wait_for_boot_quiet_window"))
            main = r'''
int main(int argc, char **argv) {
  if (argc != 4) return 2;
  now_ns = strtoll(argv[1], NULL, 10);
  pattern = atoi(argv[2]);
  interrupt_once = atoi(argv[3]);
  wait_for_boot_quiet_window();
  printf("%lld %d\n", (long long)now_ns, samples);
  return 0;
}
'''
            cfile = Path(cls.temp.name) / (label + ".c")
            cfile.write_text(HARNESS + "\n".join(functions) + main)
            for app, backport in [(1, 1), (1, 0), (0, 0)]:
                binary = Path(cls.temp.name) / f"{label}-{app}-{backport}"
                subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
                    "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                    f"-DAPP_PAYLOAD={app}", f"-DAPP_SAFE_SPEED_BACKPORT={backport}",
                    str(cfile), "-o", str(binary)], check=True)
                cls.binaries[label, app, backport] = binary

    def check_wait(self, start, pattern, expected, interrupt=0, app=1, backport=1):
        for label in ("checked_in", "generated"):
            with self.subTest(source=label):
                result = subprocess.run([str(self.binaries[label, app, backport]),
                    str(start), str(pattern), str(interrupt)], check=True,
                    capture_output=True, text=True, timeout=2)
                end, samples = map(int, result.stdout.split())
                self.assertEqual(end, expected)
                if not app or start >= 120_000_000_000:
                    self.assertEqual(samples, 0)

    def test_stable_samples_wait_for_sixty_second_floor(self):
        self.check_wait(10_000_000_000, 0, 60_000_000_000)

    def test_changing_samples_cannot_add_poll_time_to_fallback(self):
        self.check_wait(10_000_000_000, 1, 120_000_000_000)

    def test_unreadable_immediately_falls_back_to_deadline(self):
        self.check_wait(10_000_000_000, 2, 120_000_000_000)

    def test_unreadable_after_polling_keeps_original_deadline(self):
        self.check_wait(10_000_000_000, 3, 120_000_000_000)

    def test_entry_at_deadline_does_not_wait(self):
        self.check_wait(120_000_000_000, 1, 120_000_000_000)

    def test_entry_after_deadline_does_not_wait(self):
        self.check_wait(130_000_000_000, 1, 130_000_000_000)

    def test_last_poll_is_capped_to_fractional_remaining_time(self):
        self.check_wait(119_750_000_000, 1, 120_000_000_000)

    def test_interrupted_fallback_rechecks_boottime(self):
        self.check_wait(10_000_000_000, 2, 120_000_000_000, interrupt=1)

    def test_interrupted_poll_rechecks_boottime(self):
        self.check_wait(10_000_000_000, 1, 120_000_000_000, interrupt=1)

    def test_non_backport_app_still_waits_until_deadline(self):
        self.check_wait(10_000_000_000, 1, 120_000_000_000, backport=0)

    def test_non_app_does_not_wait(self):
        self.check_wait(10_000_000_000, 1, 10_000_000_000, app=0, backport=0)


class BackportReplayTests(unittest.TestCase):
    def check_replay(self, original_profile):
        paths = ["src/preload.c", "src/common.h", "src/util.c",
                 "src/kernelsnitch/kernelsnitch.h", "src/slide_app.c",
                 "src/targets/dm1q-S911BXXSAFZG1/target.h"]
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            for name in paths + ["backports/apply_dm1q_fzg1_speed.py"]:
                destination = target / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            expected = {name: (target / name).read_bytes() for name in paths}
            preload = target / "src/preload.c"
            text = preload.read_text()
            if original_profile:
                tree = ast.parse((target / "backports/apply_dm1q_fzg1_speed.py").read_text())
                needle = next(ast.literal_eval(node.value) for node in tree.body
                    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name)
                        and t.id == "needle" for t in node.targets))
                start = text.index("#if defined(APP_PAYLOAD) && APP_PAYLOAD && \\\n"
                                   "    defined(APP_SAFE_SPEED_BACKPORT)")
                end = text.index("\n__attribute__((constructor))", start)
                text = text[:start] + needle + text[end:]
            else:
                # An already-applied backport must be upgraded, not skipped
                # merely because buddy_high_order_free is present.
                old = extract_function(text, "wait_for_boot_quiet_window")
                text = text.replace(old, "static void wait_for_boot_quiet_window(void) {}", 1)
            preload.write_text(text)
            for replay in range(2):
                subprocess.run(["python3", "backports/apply_dm1q_fzg1_speed.py"],
                    cwd=target, check=True, capture_output=True, text=True, timeout=5)
                for name in paths:
                    with self.subTest(replay=replay, path=name):
                        self.assertEqual((target / name).read_bytes(), expected[name])

    def test_original_wait_is_upgraded_and_replay_preserves_sources(self):
        self.check_replay(original_profile=True)

    def test_existing_backport_is_upgraded_and_replay_preserves_sources(self):
        self.check_replay(original_profile=False)


if __name__ == "__main__":
    unittest.main()
