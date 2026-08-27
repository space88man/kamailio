# Kamailio — active development

Kamailio SIP server, `master` (~6.2dev). Language C11. Build: CMake + Ninja.
This file describes **current architecture and rules**, kept linear and
free of investigation narrative on purpose — for day-by-day campaign
status (soak results, open findings, what's in flight) see
`../reviews/HOME_STRETCH.md`; for deeper mechanism write-ups and footguns
not repeated here, see `../reviews/ARCHITECTURE.md`.

## Glossary

- **epoll** — throughout this doc (and the other write-ups) "epoll" is used
  **generically** for kamailio's `io_wait` abstraction (`io_wait.h`), which wraps
  whatever readiness mechanism the platform provides — `epoll`, `poll`, `select`,
  `kqueue`, `/dev/poll`, etc. It's simply a convenient term borrowed from Linux;
  read "epoll" / "epoll set" / "io_wait thread" as *the io_wait readiness loop*,
  not literally the Linux `epoll` syscall.
- **leaf module** — a file with no other core file depending on its internals,
  only on a small declared API. `tcp_reactor.c` is one: everything it needs from
  `tcp_main.c` comes through a handful of wrapper functions and exposed
  primitives (`tcp_conn.h`); nothing in `tcp_main.c` reaches into `tcp_reactor.c`'s
  statics.

## Branches & upstream

- **Upstream is `master`.** `origin/master` tracks upstream master closely.
  Treat `origin/master` as the baseline.
- **`master.*`** — research/fix branches off master (mode-0/1 + shared-core
  work, e.g. TCP close-event fixes). Example: `master.fix3`.
- **`reactor.NNN`** — the mode-2 TCP reactor feature. Current tip:
  `reactor.111j`, rebased on `origin/master`, **6 commits laid out by file
  set** (not by development increment — don't expect a commit in the
  middle to build standalone). Verify freshness with `git log --oneline
  origin/master..HEAD` before assuming this is still current; branches
  get rebased regularly during the pre-merge campaign.
  1. `core: prerequisites for the TCP threaded receiver mode` — cmake mutex/
     thread-naming probe + the process-shared condvar (`tcp_cond.*`) + the
     serialized-pkg_malloc scaffolding (`tcp_reactor_mem.*`)
  2. `core: tcp reactor - pool, dispatch socket and connection state` — the
     reactor as a self-contained module (`tcp_reactor.*`, `tcp_conn.h`,
     `tcp_server.h`, the `tcp_reactor_threads` cfg.y directive)
  3. `core: wire the tcp reactor into tcp_main and tcp workers` — the
     integration points (`tcp_main.c`, `tcp_read.c`/`.h`, `tcp_mtops.*`,
     `tls_hooks.h`)
  4. `msrp: update to handle TCP mode = 2`
  5. `websocket: update to handle TCP mode = 2`
  6. `tls: dispatch event route to worker`

  Keep that layering for future changes on top: core changes fold into the
  `core:` commits (2 or 3, whichever owns the touched file — see "Key files"),
  module changes get their own commit and stay last, same as 4-6.
- The TCP close-event fixes (earlier, unrelated work) are submitted
  upstream separately from this branch. `origin/master` contains them
  (`8bfb74bb` *"core: tcp - fix close events missing or wrong reason"*),
  but a released kamailio may not — don't assume they exist in an
  arbitrary checkout.
- Current PR/merge status, build verification state, and soak-test
  results live in `../reviews/HOME_STRETCH.md`, not here — that's the
  living tracker; this file stays architecture-only.

## Build

```sh
cmake -G Ninja \
  -DCMAKE_INSTALL_PREFIX=/work/richard/Projects/kamailio/run \
  -DCMAKE_INSTALL_LOCALSTATEDIR=/var \
  -S . -B ../builds/build \
  -DINCLUDE_MODULES="app_python3 app_python3s tls tls_wolfssl outbound db_mysql db_unixodbc db_postgres http_async_client"
cmake --build ../builds/build
```

Single-TU rebuild (fast sanity check), e.g. tcp_main.c:
`ninja -C ../builds/build src/CMakeFiles/kamailio.dir/core/tcp_main.c.o`

The legacy `make`-based build system also works (verified 27 Aug 2026),
but needs its own `env.sh`-driven module list kept current against the
actual `src/modules/` tree, and its `pthread_setname_np`/
`PTHREAD_MUTEX_ROBUST` support gracefully degrades with no equivalent
CMake probe. Details: `../reviews/ARCHITECTURE.md` footguns #3 and #6.

## Memory allocation — MANDATORY

- Never use system `malloc`/`free`.
- Per-process heap: `pkg_malloc` / `pkg_free`.
- Cross-process shared: `shm_malloc` / `shm_free`.
- Wrong allocator = silent corruption or crash.

## Logging macros

`LM_ERR` / `LM_WARN` / `LM_INFO` / `LM_DBG` (DBG compiled out in production).

## TCP threading modes — `ksr_tcp_main_threads` (in `globals.h`)

Note the `ksr_` prefix; it is **not** `tcp_main_threads`.

- `0` = legacy fd-passing, no trampolines. Kamailio's own compiled-in
  default — but a site's `kamailio-local.cfg` can (and often does)
  override this via `#!trydefenv TCP_MAIN_THREADS`/`#!ifdef`, defaulting
  to a different mode when the env var is unset. **Check the actual
  `kamailio-local.cfg` in use, don't assume mode 0 just because no env
  var was passed.**
- `1` = legacy fd-passing + OpenSSL trampoline (workers relay TLS/crypto
  calls to `PROC_TCP_MAIN` over a socketpair, `tcp_mtops.c`).
- `2` = full TCP reactor (the mode-2 feature; developed on `reactor.NNN`).

Pool size in mode 2: `ksr_tcp_reactor_threads` (default 8, `tcp_reactor_threads`
cfg.y directive; defined in `tcp_reactor.c`, not `tcp_main.c`).

**Mode 0/1's connection ownership is not a one-time handoff** — a
connection ping-pongs between worker-owned (while messages keep arriving
within 5s of each other) and `tcp_main`-shepherded (after any 5s+ idle
gap, re-dispatched via `send2child()` on the next read). Full mechanism,
code citations, and why this matters for load testing:
`../reviews/ARCHITECTURE.md`.

## Mode-2 reactor — how it works

`tcp_reactor.c` is a **leaf module**: it owns all mode-2 state (the dispatch
socketpair, the thread pool, per-connection shield/job bookkeeping) behind a
small public API declared in `tcp_reactor.h` (~12 functions). `tcp_main.c` holds
only the integration points — one call-out per existing io dispatch location —
plus two things `tcp_reactor.c` cannot own itself: the `io_wait` set (`io_h`)
and the local timer (`tcp_main_ltimer`), both still `static` to `tcp_main.c` on
purpose (see the last bullet below).

Two tiers inside `PROC_TCP_MAIN`:

1. **One io_wait/epoll thread — a dispatcher.** Owns the epoll set, all connection
   fds, and the timers. On read-readiness it does **not** frame inline: it
   *shields* the connection (removes from epoll+timer, `F_CONN_POOL_BUSY`, takes an
   in-pool ref) and hands it to the pool. The only wire bytes it touches inline are
   the HAProxy/PROXY header at accept. Entry point: `handle_tcpconn_ev()` in
   `tcp_main.c` calls straight into `tcp_reactor_handle_tcpconn_ev()`.
2. **A pool of reactor threads** (`ksr_tcp_reactor_threads`; `tcp_reactor.*`,
   `tcp_cond.*`). Does all POLLIN work: framing/reassembly, TLS
   (handshake/encrypt/decrypt), dispatch to workers, write-flush.

Read path: **io_wait detects readiness → shield → hand to pool → pool frames →
completion re-arms (unshield) or chains another job.** Unlike mode 0/1
(where a connection stays with its worker for free during bursts, see
above), mode 2 re-runs this shield/unshield cycle on **every** read event
— continuous rebalancing instead of sticky-until-idle assignment. That
tradeoff (mode 2 wins connection-establishment latency under burst, mode
0/1 wins per-message latency once already connected) is measured with
matched-N data in `../reviews/HOME_STRETCH.md`.

- **Framing reuses `tcp_read.c`** (`tcp_read_req` / `tcp_read_data`) — the *same*
  functions as mode 0, just run on a pool thread.
- **Dispatch:** a fully-framed SIP/HEP3/MSRP/WS message becomes a small shm task
  written to an AF_UNIX `SOCK_DGRAM` socketpair (`ksr_tcp_reactor_dsock`, private
  to `tcp_reactor.c` — `ksr_tcp_reactor_get_dispatch_rfd/wfd()` are the only way
  in); TCP workers `recvfrom` it and run `receive_msg()`. So **`receive_msg()`
  always runs single-threaded in a worker, never on a pool thread** — WS included
  (`ws_deliver_sip` → `tcp_reactor_dispatch_msg`).
- **Writes:** async write path only when `ksr_tcp_main_threads > 0` (no fd-passing
  for writes). A worker enqueues via `tcp_reactor_send_put()`; tcp_main's
  `CONN_WRITE_REQ` arm is a one-line call-out to `tcp_reactor_handle_write_req()`,
  which stages the payload and, if the connection is free, shields it and
  enqueues a `TCP_R_WRITE` job so TLS encoding also happens on a pool thread —
  never inline in the io_wait thread or in a worker.
- **Outbound connect (mode 2):** a worker sends `CONN_CONNECT_REQ`; tcp_main's arm
  calls `tcp_reactor_handle_connect_req()`, which does the dedup re-check
  (another worker may have raced it to the same destination), `connect()`, and
  promotion entirely in-process — no worker-owned connect fd, no fd-passing.
- **`tcp_script_mode = 0` is honoured.** A worker holds no fd/`tcp_connection` in
  mode 2, so it can't drop the connection locally the way modes 0/1 do inline
  on a negative `receive_msg()`/script result; instead it sends `CONN_SCRIPT_CLOSE`
  (connection id only, from `rcv->proto_reserved1`) and tcp_main's arm calls
  `tcp_reactor_handle_script_close()` to tear it down the same way `CONN_EOF`
  does.
- **`io_h`/`tcp_main_ltimer` stay in `tcp_main.c`, on purpose.** `io_watch_add/
  _del/_chg()` are `inline static` functions defined inside `io_wait.h`, freshly
  instantiated per translation unit against a locally-defined `enum fd_types`
  (`HANDLE_IO_INLINE`) — `tcp_reactor.c` including `io_wait.h` itself would mean
  defining its own, separately-numbered `fd_type`. Instead `tcp_conn.h` declares
  `tcpmain_io_watch_add_conn/_del/_chg()` and `tcpmain_local_timer_add/_del()`,
  implemented in `tcp_main.c`, that `tcp_reactor.c` calls instead. Callable only
  from the io_wait thread — same rule as the calls they forward to. This also
  keeps "only the io_wait thread touches `io_h`" a compiler-checked fact (`io_h`
  is `static`) instead of a convention every future change has to remember —
  several of the concurrency bugs found while landing this branch were exactly
  "something touched `io_h`/the timer from a pool thread or a stale-state IPC
  handler."

## Invariants — preserve on every commit

1. `ksr_tcp_main_threads == 0`: legacy fd-passing path UNCHANGED.
2. `== 1`: fd-passing + TLS trampoline UNCHANGED (`_tconfd(c)` selects the fd copy
   in `PROC_TCP_MAIN`).
3. `== 2`: full reactor, no fd-passing for reads or writes.
4. No direct OpenSSL calls in worker read paths at any non-zero mode — the
   trampoline confines OpenSSL to `PROC_TCP_MAIN` (single-process constraint;
   the crypto/pthread shared-memory hooks are not installed there). This is
   *why* mode 1/2 never need `tls_threads_mode=2`, while mode 0 (every
   worker does its own OpenSSL independently) does — see the
   `TLS_THREADS_MODE` footgun in `../reviews/ARCHITECTURE.md`, a real,
   reproducible server-wide hang if missed.
5. `io_h`/`tcp_main_ltimer` are touched only from the io_wait thread, only via
   direct `io_watch_*()`/`local_timer_*()` calls in `tcp_main.c` itself or via
   the `tcpmain_*` wrappers from `tcp_reactor.c` — never add a second path in.

## `pkg_malloc` on pool threads — caveat

`pkg_malloc` is per-process, lock-free, and **not thread-safe**. In mode 2 several
pool threads can call it (WS control-frame encode does, in `ws_frame.c` — the WS
frame codec runs directly on a pool thread, unlike other protocols which hand a
fully-framed message to a worker). A process-local allocator lock is installed in
`PROC_TCP_MAIN` (`tcp_reactor_pkg_lock_install`, `tcp_reactor_mem.*`, installed
right before the pool threads are spawned); any new pool-thread `pkg_malloc` is
safe *only* because of it. SIP/HEP3/MSRP codecs are pkg-clean (they `shm_malloc`
the dispatch task); TLS scratch is `_Thread_local`. Full analysis:
`../PKG_MALLOC.md`.

## Connection close events

Routes `tcp:closed` / `tcp:timeout` / `tcp:reset` (module `tcpops`). Flow:
`con->event` (reason) → `tcp_emit_closed_event()` → `SREV_TCP_CLOSED` → tcpops
handler → the event route. The emitter is defined in `tcp_main.c` (used there
directly, and exposed via `tcp_conn.h` for `tcp_reactor.c` to call) and runs in
`PROC_TCP_MAIN` (both modes); it is **fire-once** per connection
(`F_CONN_CLOSE_EV_SENT`). Mode 2 emits at the pool/inline read-teardown and
script-close choke points too. Full write-up + validation: `../TCP_EVENTSv2.md`.

## Framing approach — pragmatic, not OpenSIPS-shaped

Detect the framing and branch with plain if/else/switch to the existing
per-protocol handler (`tcp_read_req` for SIP, `hep3_process_msg`,
`msrp_process_msg`, WS). Kamailio has **no** protocol-abstraction layer and should
not grow one for this. OpenSIPS's protocol plugin layer has no kamailio
equivalent — read it for ideas, stop at that boundary.

## Key files

| File | Role |
|---|---|
| `src/main.c` | startup, `ksr_tcp_main_threads` init |
| `src/core/tcp_main.c` | `PROC_TCP_MAIN` loop; mode-2 is thin call-outs into `tcp_reactor.c` at each io dispatch point, plus the `tcpmain_*` wrappers around `io_h`/`tcp_main_ltimer` — not the primary target for reactor-logic changes anymore, see `tcp_reactor.c` |
| `src/core/tcp_reactor.*` | mode-2 leaf module and **primary change target**: pool, dispatch socket, shield/job state machine, write/connect/script-close/tls-event handling. Small declared API in `tcp_reactor.h`; everything else `static` |
| `src/core/tcp_reactor_mem.*` | serializes `pkg_malloc` for `PROC_TCP_MAIN` only (see the caveat above) |
| `src/core/tcp_read.c` | framing (SIP/HEP3/MSRP/WS), reassembly, dispatch, close-reason classification; worker-side consumption of dispatched tasks and `tcp_script_mode=0` stay here, not in `tcp_reactor.c` (see below) |
| `src/core/tcp_cond.*` | process-shared condvar feeding the pool |
| `src/core/tcp_mtops.c` | TLS trampoline (mode 1/2); mode 2 pool threads take a direct-call path (`KSR_TCPX_MAIN_PIDX`) instead of the mode-1 socketpair relay, since they already run inside `PROC_TCP_MAIN` |
| `src/core/io_wait.*` | epoll abstraction (tcp_main + workers); `tcp_reactor.c` deliberately does **not** include this — see the `io_h`/`tcp_main_ltimer` bullet above |
| `src/core/tcp_conn.h` | `struct tcp_connection`, `F_CONN_*` flags, `conn_cmds`, plus the `tcp_main.c` internals (`tcpconn_try_unhash`/`_put_destroy`/etc., `tcpmain_io_watch_*`/`_local_timer_*`) exposed for `tcp_reactor.c` |
| `src/modules/tls/tls_server.c` | OpenSSL integration (via trampoline); `tls_run_event_routes()` dispatches `tls:connection-out` to a worker in mode 2 (`tcp_reactor_dispatch_tls_event`) |
| `src/modules/tcpops/` | close-event routes |

`tcp_read.c` staying separate from `tcp_reactor.c` is deliberate, not an
oversight: the worker-side dispatch consumption calls `hep3_process_msg()`,
which is `static` to `tcp_read.c` and already shared between modes 0/1 (inline)
and mode 2 (dispatched) — moving it would mean exposing yet another primitive
for one caller.

## Hard rules

- No writes via fd-passing when `ksr_tcp_main_threads > 0`.
- No direct `malloc`/`free` anywhere.
- No OpenSSL in worker read paths (use the trampoline).
- The `ksr_tcp_main_threads == 0` path must stay fully functional after every commit.
- `tcp_reactor.c` does not include `io_wait.h` and does not touch `io_h`/
  `tcp_main_ltimer` directly — go through the `tcpmain_*` wrappers in `tcp_conn.h`.
- New core code in `src/core/`; modules in `src/modules/`.
- Testing is done on a separate VM (`degas.voip.test`, see
  `../client-test/degas/SUT-VM.md`) — do not probe locally-installed
  binaries.
- After **any** kamailio restart on the test VM, verify RPC responsiveness
  explicitly (`kamctl rpc core.uptime`, short timeout) before trusting
  process-alive checks — a real, reproducible failure mode leaves the
  process looking fully alive (listening, correct process count) while
  totally unresponsive. See the `TLS_THREADS_MODE` footgun,
  `../reviews/ARCHITECTURE.md`.

## Reference (workspace root, `../`, and `../reviews/`)

- `../reviews/ARCHITECTURE.md` — durable architecture reference and
  footgun list (connection-lifecycle mechanics, timer ownership, build/
  test gotchas) — start here for anything not already covered above.
- `../reviews/HOME_STRETCH.md` — living day-by-day campaign status:
  current PR/merge state, soak-test results, open findings.
- `../reviews/PERFORMANCEv2.md` — deep historical performance record
  (methodology, full mode-0/1/2 comparisons, findings to date).
- `../reviews/TESTS.md` — what each client-side test script validates and
  how to run it (split-client sweep, 100cps call-flow, p2p in-dialog
  smoke).
- `../TCP_EVENTSv2.md` — settled close-event write-up (mode 0 + mode 2). Supersedes
  the older `../TCP_EVENTS.md`, which contains investigation dead-ends — do not use it.
- `../FUTURE_WORK.md` — deferred work (check this file's own list before
  assuming anything on it is still open).
- `../PKG_MALLOC.md` — pkg allocator thread-safety.
- `../opensips` — read-only OpenSIPS 4.0.0 reference (design ideas only).
