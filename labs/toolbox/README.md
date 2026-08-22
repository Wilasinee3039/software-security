# Lab toolbox (Docker-first)

Most labs run as their own containers (`docker compose up`). A few weeks need a **Linux
dev/attacker shell** with tools that don't run cleanly on a Windows/macOS host:

- **Week 11 (memory safety):** `clang` + **libFuzzer** + ASan + `gdb` — Apple clang ships no
  libFuzzer runtime, and `gdb` is painful on macOS, so use this container.
- **Weeks 4 / 10 (optional recon):** `nmap`, `sqlmap`.

This replaces the full Kali VM for those weeks. (A VM is still a fine optional fallback if your
host can't run Docker.)

## Build (once)
```bash
docker build -t softsec-toolbox labs/toolbox
```

## Run (mount the week's folder)
`--cap-add=SYS_PTRACE` + relaxed seccomp let `gdb` and ASan work:
```bash
docker run -it --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v "$PWD":/work -w /work softsec-toolbox
# inside: clang -g -fsanitize=address,fuzzer fuzz_harness.c -o fuzz && ./fuzz
```

Includes: clang 19 + libFuzzer/ASan, gdb, nmap, sqlmap, python3, git, curl.
