/*
 * Copyright 2006, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "crasher"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// We test both kinds of logging.
#include <android-base/logging.h>
#include <log/log.h>

#if defined(STATIC_CRASHER)
#include "debuggerd/handler.h"
#endif

#define noinline __attribute__((__noinline__))

// Avoid name mangling so that stacks are more readable.
extern "C" {

void crash1(void);
void crashnostack(void);

int do_action(const char* arg);

noinline void maybe_abort() {
    if (time(0) != 42) {
        abort();
    }
}

char* smash_stack_dummy_buf;
noinline void smash_stack_dummy_function(volatile int* plen) {
  smash_stack_dummy_buf[*plen] = 0;
}

// This must be marked with "__attribute__ ((noinline))", to ensure the
// compiler generates the proper stack guards around this function.
// Assign local array address to global variable to force stack guards.
// Use another noinline function to corrupt the stack.
noinline int smash_stack(volatile int* plen) {
    printf("%s: deliberately corrupting stack...\n", getprogname());

    char buf[128];
    smash_stack_dummy_buf = buf;
    // This should corrupt stack guards and make process abort.
    smash_stack_dummy_function(plen);
    return 0;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winfinite-recursion"

void* global = 0; // So GCC doesn't optimize the tail recursion out of overflow_stack.

noinline void overflow_stack(void* p) {
    void* buf[1];
    buf[0] = p;
    global = buf;
    overflow_stack(&buf);
}

#pragma clang diagnostic pop

noinline void* thread_callback(void* raw_arg) {
    const char* arg = reinterpret_cast<const char*>(raw_arg);
    return reinterpret_cast<void*>(static_cast<uintptr_t>(do_action(arg)));
}

noinline int do_action_on_thread(const char* arg) {
    pthread_t t;
    pthread_create(&t, nullptr, thread_callback, const_cast<char*>(arg));
    void* result = nullptr;
    pthread_join(t, &result);
    return reinterpret_cast<uintptr_t>(result);
}

noinline int crash3(int a) {
    *reinterpret_cast<int*>(0xdead) = a;
    return a*4;
}

noinline int crash2(int a) {
    a = crash3(a) + 2;
    return a*3;
}

noinline int crash(int a) {
    a = crash2(a) + 1;
    return a*2;
}

noinline void abuse_heap() {
    char buf[16];
    free(buf); // GCC is smart enough to warn about this, but we're doing it deliberately.
}

noinline void sigsegv_non_null() {
    int* a = (int *)(&do_action);
    *a = 42;
}

noinline void fprintf_null() {
    fprintf(nullptr, "oops");
}

noinline void readdir_null() {
    readdir(nullptr);
}

noinline int strlen_null() {
    char* sneaky_null = nullptr;
    return strlen(sneaky_null);
}

static int usage() {
    fprintf(stderr, "usage: %s KIND\n", getprogname());
    fprintf(stderr, "\n");
    fprintf(stderr, "where KIND is:\n");
    fprintf(stderr, "  smash-stack           overwrite a -fstack-protector guard\n");
    fprintf(stderr, "  stack-overflow        recurse until the stack overflows\n");
    fprintf(stderr, "  heap-corruption       cause a libc abort by corrupting the heap\n");
    fprintf(stderr, "  heap-usage            cause a libc abort by abusing a heap function\n");
    fprintf(stderr, "  nostack               crash with a NULL stack pointer\n");
    fprintf(stderr, "  abort                 call abort()\n");
    fprintf(stderr, "  assert                call assert() without a function\n");
    fprintf(stderr, "  assert2               call assert() with a function\n");
    fprintf(stderr, "  exit                  call exit(1)\n");
    fprintf(stderr, "  fortify               fail a _FORTIFY_SOURCE check\n");
    fprintf(stderr, "  LOG_ALWAYS_FATAL      call liblog LOG_ALWAYS_FATAL\n");
    fprintf(stderr, "  LOG_ALWAYS_FATAL_IF   call liblog LOG_ALWAYS_FATAL_IF\n");
    fprintf(stderr, "  LOG-FATAL             call libbase LOG(FATAL)\n");
    fprintf(stderr, "  SIGFPE                cause a SIGFPE\n");
    fprintf(stderr, "  SIGSEGV               cause a SIGSEGV at address 0x0 (synonym: crash)\n");
    fprintf(stderr, "  SIGSEGV-non-null      cause a SIGSEGV at a non-zero address\n");
    fprintf(stderr, "  SIGSEGV-unmapped      mmap/munmap a region of memory and then attempt to access it\n");
    fprintf(stderr, "  SIGTRAP               cause a SIGTRAP\n");
    fprintf(stderr, "  fprintf-NULL          pass a null pointer to fprintf\n");
    fprintf(stderr, "  readdir-NULL          pass a null pointer to readdir\n");
    fprintf(stderr, "  strlen-NULL           pass a null pointer to strlen\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "prefix any of the above with 'thread-' to run on a new thread\n");
    fprintf(stderr, "prefix any of the above with 'exhaustfd-' to exhaust\n");
    fprintf(stderr, "all available file descriptors before crashing.\n");
    fprintf(stderr, "prefix any of the above with 'wait-' to wait until input is received on stdin\n");

    return EXIT_FAILURE;
}

noinline int do_action(const char* arg) {
    // Prefixes.
    if (!strncmp(arg, "wait-", strlen("wait-"))) {
      char buf[1];
      TEMP_FAILURE_RETRY(read(STDIN_FILENO, buf, sizeof(buf)));
      return do_action(arg + strlen("wait-"));
    } else if (!strncmp(arg, "exhaustfd-", strlen("exhaustfd-"))) {
      errno = 0;
      while (errno != EMFILE) {
        open("/dev/null", O_RDONLY);
      }
      return do_action(arg + strlen("exhaustfd-"));
    } else if (!strncmp(arg, "thread-", strlen("thread-"))) {
        return do_action_on_thread(arg + strlen("thread-"));
    }

    // Actions.
    if (!strcasecmp(arg, "SIGSEGV-non-null")) {
        sigsegv_non_null();
    } else if (!strcasecmp(arg, "smash-stack")) {
        volatile int len = 128;
        return smash_stack(&len);
    } else if (!strcasecmp(arg, "stack-overflow")) {
        overflow_stack(nullptr);
    } else if (!strcasecmp(arg, "nostack")) {
        crashnostack();
    } else if (!strcasecmp(arg, "exit")) {
        exit(1);
    } else if (!strcasecmp(arg, "crash") || !strcmp(arg, "SIGSEGV")) {
        return crash(42);
    } else if (!strcasecmp(arg, "abort")) {
        maybe_abort();
    } else if (!strcasecmp(arg, "assert")) {
        __assert("some_file.c", 123, "false");
    } else if (!strcasecmp(arg, "assert2")) {
        __assert2("some_file.c", 123, "some_function", "false");
    } else if (!strcasecmp(arg, "fortify")) {
        char buf[10];
        __read_chk(-1, buf, 32, 10);
        while (true) pause();
    } else if (!strcasecmp(arg, "LOG(FATAL)")) {
        LOG(FATAL) << "hello " << 123;
    } else if (!strcasecmp(arg, "LOG_ALWAYS_FATAL")) {
        LOG_ALWAYS_FATAL("hello %s", "world");
    } else if (!strcasecmp(arg, "LOG_ALWAYS_FATAL_IF")) {
        LOG_ALWAYS_FATAL_IF(true, "hello %s", "world");
    } else if (!strcasecmp(arg, "SIGFPE")) {
        raise(SIGFPE);
        return EXIT_SUCCESS;
    } else if (!strcasecmp(arg, "SIGTRAP")) {
        raise(SIGTRAP);
        return EXIT_SUCCESS;
    } else if (!strcasecmp(arg, "fprintf-NULL")) {
        fprintf_null();
    } else if (!strcasecmp(arg, "readdir-NULL")) {
        readdir_null();
    } else if (!strcasecmp(arg, "strlen-NULL")) {
        return strlen_null();
    } else if (!strcasecmp(arg, "heap-usage")) {
        abuse_heap();
    } else if (!strcasecmp(arg, "SIGSEGV-unmapped")) {
        char* map = reinterpret_cast<char*>(mmap(nullptr, sizeof(int), PROT_READ | PROT_WRITE,
                                                 MAP_SHARED | MAP_ANONYMOUS, -1, 0));
        munmap(map, sizeof(int));
        map[0] = '8';
    } else {
        return usage();
    }

    fprintf(stderr, "%s: exiting normally!\n", getprogname());
    return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
#if defined(STATIC_CRASHER)
    debuggerd_callbacks_t callbacks = {
      .get_abort_message = []() {
        static struct {
          size_t size;
          char msg[32];
        } msg;

        msg.size = strlen("dummy abort message");
        memcpy(msg.msg, "dummy abort message", strlen("dummy abort message"));
        return reinterpret_cast<abort_msg_t*>(&msg);
      },
      .post_dump = nullptr
    };
    debuggerd_init(&callbacks);
#endif

    if (argc == 1) crash1();
    else if (argc == 2) return do_action(argv[1]);

    return usage();
}

};
