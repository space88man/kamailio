# Kamailio TCP architecture — durable reference

Campaign-independent reference, meant to augment `CLAUDE.md` for future
work on this codebase. Where `CLAUDE.md` already covers something in
depth (mode-2's two-tier pool design, the `io_h`/`tcp_main_ltimer`
ownership rule, `pkg_malloc` thread-safety), this doc cross-references
rather than duplicates. What's here is either genuinely new ground (the
mode-0/1 connection-ownership lifecycle, which turned out to be more
subtle than it first looks) or footguns worth not re-discovering the hard
way. Assumes mode-2 (the reactor) has landed — described as the current
architecture, not a pending feature.

Note on `CLAUDE.md`'s own text: its "Mental model" framing (also in
`PERFORMANCEv2.md`/`HOME_STRETCH.md`) currently says mode 0/1's dispatch
decision, once made, "is then permanently sticky for the connection's
whole life (the fd physically lives in one child's fd table once handed
over)." That's not quite right — see below. Worth fixing at the source
next time `CLAUDE.md` gets a pass; not changed here since this doc's job
is to be the detailed reference, not to edit `CLAUDE.md` unprompted.

## TCP threading modes (`ksr_tcp_main_threads`, note the `ksr_` prefix)

- **0** — legacy fd-passing, no trampolines.
- **1** — legacy fd-passing + OpenSSL trampoline (workers relay TLS/crypto
  calls to `PROC_TCP_MAIN` over a socketpair instead of calling OpenSSL
  themselves — `tcp_mtops.c`).
- **2** — full TCP reactor (`tcp_reactor.c`): one io_wait dispatcher thread
  + a pool of reactor threads inside `PROC_TCP_MAIN`, `AF_UNIX SOCK_DGRAM`
  dispatch socket to workers. Full design in `CLAUDE.md`'s "Mode-2
  reactor — how it works" section; not repeated here.

A site's `kamailio-local.cfg` can (and, on this campaign's SUT, does)
override kamailio's own compiled-in default via `#!trydefenv
TCP_MAIN_THREADS` / `#!ifdef` — the SUT defaults to `tcp_main_threads=2`
when the env var is unset, not kamailio's own upstream default of `0`.
**Always grep the actual `kamailio-local.cfg` in use for `#!trydefenv`/
`#!ifdef ENVVAR` patterns before assuming a documented default applies —
site config can and does override it, silently.**

## Mode 0/1: connection ownership is a ping-pong, not a one-time handoff

The one-shot picture ("`send2child()` decides once, then the fd lives in
that child forever") is incomplete. The real cycle:

1. **New connection**: `tcp_main` accepts, calls `send2child()` — picks
   the least-busy worker (round-robin over all children, or per-socket-
   group least-busy if `tcp_sockets_gworkers` is configured), and hands
   the fd via `send_fd()` (`sendmsg()` + `SCM_RIGHTS` over a UNIX socket).
   The worker adds it to **its own** local epoll set exactly once
   (`io_watch_add(&io_w, ...)`, `tcp_read.c:2116`, only in the
   `F_TCPMAIN`-handoff case) and reads it directly from then on — no
   further round-trip through `tcp_main` for as long as it keeps reading.
2. **Every successful read extends a 5-second idle timer**:
   `con->timeout = get_ticks_raw() + S_TO_TICKS(TCP_CHILD_TIMEOUT)`
   (`tcp_read.c:2298`).
3. **After 5s with no read activity, the child returns the connection to
   `tcp_main`.** `TCP_CHILD_TIMEOUT`'s own definition says so outright
   (`tcp_conn.h:42-44`):

```c
#define TCP_CHILD_TIMEOUT \
    5    /* after 5 seconds, the child "returns"
          * the connection to the tcp main process */
```

   The child's `tcpconn_read_timeout()` (a local-timer-wheel callback)
   fires `release_tcpconn(c, CONN_RELEASE, tcpmain_sock)`, closing only
   its **own local copy** of the fd — `tcp_main` kept its own fd open the
   whole time via the fd-passing `dup`, it never fully let go.
4. **`tcp_main`'s `CONN_RELEASE` handler** (`tcp_main.c:4207-4334`,
   comment: *"the connection is returning to service"*) re-adds the fd to
   **its own** `io_h`, arms its **own** shepherding timer
   (`tcpconn_main_timeout`), flags the connection `F_CONN_MAIN_TIMER`.
5. **Next read event on a `tcp_main`-shepherded connection →
   `tcp_main` calls `send2child()` again** — same dispatch path, same
   `queue-full` exposure as the original setup. Confirmed at
   `tcp_main.c:5058-5066`: `handle_tcpconn_ev()` branches explicitly on
   `ksr_tcp_main_threads == 2` to skip this (mode 2 owns the fd
   permanently, no fd-passing at all); mode 0/1 falls through to
   `goto send_to_child`.

**Net effect**: a connection is pinned to one worker for free only while
messages keep arriving within 5s of each other (true for back-to-back
call signaling — INVITE/ACK/BYE close together). Any real traffic pattern
with a 5+ second gap between messages — the ordinary case for a
REGISTER'd-but-otherwise-quiet endpoint between calls — bounces the
connection back through `tcp_main` and back through `send2child()` on
every reactivation, and may land on a **different** worker each time
(the least-busy heuristic is re-evaluated fresh each time).

Architecturally this is closer in *spirit* to mode-2's shield/unshield
than it first looks — both designs release a connection when not
actively needed and reclaim it on next activity. They differ in
granularity: mode-0's release is a coarse 5s idle gate (bursts of
back-to-back activity stay pinned, cheap); mode-2's is per-event (every
single message pays the shield/dispatch/unshield cost, in exchange for
continuous rebalancing instead of sticky-until-idle assignment). See
`PERFORMANCEv2.md`/`HOME_STRETCH.md` for the matched-N latency numbers
this produces in practice (mode-2 wins connection-establishment latency
under burst; mode-0 wins single-message post-connect latency, since it
has fewer hops once a worker owns the fd — the tradeoff is real in both
directions, not a strict win for either mode).

**Does the idle-release itself cost anything on an already-established
connection?** Measured directly (`HOME_STRETCH.md`, 27 Aug): in
isolation, no — a HOT/COLD `OPTIONS` probe (2s vs 7s gaps) showed
~5ms either way, 0 `queue-full`. Under concurrent background load
(matching the daily sweep's contention pattern), the tax shows up but
**probabilistically, not on every reactivation** — one 128ms spike out
of six COLD samples, gated by whether the reactivation's `send2child()`
call happens to land during someone else's active burst (load itself
runs in waves, not continuously). Same mechanism as the burst-setup tax
above, just conditional rather than deterministic when it's an existing
connection reactivating rather than a fresh one connecting.

### `send2child()`'s backoff queue — not fatal under burst

`send2child()`'s `send_fd()` can return `EAGAIN` (kernel socket buffer
between `tcp_main` and the target worker is momentarily full — the
worker hasn't drained it fast enough). This is logged as `CRITICAL:
... queue full` but is **not** a dropped connection:

- `SEND_FD_QUEUE` is unconditionally compiled in (`tcp_main.c:128`, not a
  build option).
- On `EAGAIN`, the pending handoff is pushed onto an in-memory retry
  queue (`send2child_q`) that starts at 128 slots
  (`SEND_FD_QUEUE_SIZE`) and **dynamically doubles** (`pkg_realloc`) up
  to `tcp_main_max_fd_no` (`MAX_SEND_FD_QUEUE_SIZE`) — sized to absorb a
  burst, not overflow into it.
- Retried opportunistically on every subsequent pass through the io_wait
  event loop (`send_fd_queue_run()`, called from ~7 branches of the
  epoll dispatch loop).
- Each entry gets 2 seconds (`SEND_FD_QUEUE_TIMEOUT`) to succeed before
  being dropped.
- The underlying TCP connection was **already accepted at the kernel
  level** the moment any of this starts — nothing about the client's
  connection is refused or reset; the client just sees its response
  arrive later than usual once the handoff clears.

Don't treat `queue-full` CRITICAL log lines alone as proof of a
client-visible regression — always cross-check actual setup-failure
counts. It's easy to trigger under concurrent-burst new-connection load
(many simultaneous SYNs against few `children=N` workers) or under
idle-reconnection load (many connections reactivating after a 5s+ gap at
once) — and, per direct comparison against stock `origin/master` at
identical load, this is pre-existing legacy behavior, not something any
given branch's changes are likely to have introduced. Verify against
stock master at matched load before attributing a `queue-full` finding to
new code.

## Mode 2: OpenSSL confinement and why `pkg_malloc` needs a lock there

Full reactor design: `CLAUDE.md`. Two points worth restating here because
they explain *why* certain footguns below are mode-dependent:

- **OpenSSL is confined to a single process.** Mode 1 relays TLS/crypto
  calls from workers to `PROC_TCP_MAIN` over a socketpair; mode 2's pool
  threads call OpenSSL directly since they already run inside
  `PROC_TCP_MAIN`. Either way, for the TCP/TLS path specifically, only
  **one process** ever touches OpenSSL — no multi-process contention on
  OpenSSL's internal state is possible for that path, structurally, in
  mode 1/2.
- **`pkg_malloc` is per-process, lock-free, not thread-safe** — normally
  fine (one thread per process in kamailio's classic model), but mode 2
  has multiple pool threads in the *same* process potentially calling it
  concurrently (WS control-frame encoding does this directly on a pool
  thread). A process-local allocator lock is installed in `PROC_TCP_MAIN`
  (`tcp_reactor_pkg_lock_install`, right before pool threads spawn)
  specifically to make this safe. Full analysis: `PKG_MALLOC.md`.

## Timers / timer wheels — who owns which

| Timer | Owner | Purpose |
|---|---|---|
| `tcp_reader_ltimer` | each worker (child), local | drives `tcpconn_read_timeout` — the 5s `TCP_CHILD_TIMEOUT` idle-release-to-`tcp_main` check |
| `tcp_main_ltimer` | `tcp_main` only, `static` | drives `tcpconn_main_timeout` — the shepherding timer for connections `tcp_main` currently owns (both freshly-accepted-but-not-yet-dispatched, and idle-released-back connections); also owns mode-2's io_wait-thread timer duties |
| pool-thread-local timers | N/A | mode 2's pool threads don't own timers — `tcp_reactor_shield()` explicitly removes a connection from `tcp_main_ltimer` before handing it to the pool, `unshield` re-arms it |

`io_h` and `tcp_main_ltimer` are deliberately kept `static` to
`tcp_main.c` — see `CLAUDE.md`'s explanation (`tcpmain_io_watch_*`/
`tcpmain_local_timer_*` wrapper functions, callable only from the io_wait
thread). This is a compiler-enforced "only the io_wait thread touches
these" invariant, adopted after real concurrency bugs during mode-2's
development traced back to exactly this kind of cross-thread touch.

Related, smaller timing constants worth knowing (`tcp_conn.h`):
`TCP_MAIN_SELECT_TIMEOUT` (5s, how often `tcp_main` polls for timeouts in
its own select/epoll loop) and `TCP_CHILD_SELECT_TIMEOUT` (2s, same for
children) — these bound the *granularity* of timeout checking, not the
timeout durations themselves.

## Footguns

1. **`TLS_THREADS_MODE` / `tls_threads_mode=2` is required only for mode
   0** — not mode 1, and this distinction matters, don't over-apply the
   fix. The hazard is specifically *multiple processes independently
   calling into OpenSSL concurrently after fork*. Mode 0 has exactly that:
   every worker does its own SIP-TLS handshake independently, so N
   processes race each other's OpenSSL init. Mode 1 and mode 2 don't —
   both confine *all* OpenSSL calls to a single process (`PROC_TCP_MAIN`)
   via the trampoline (mode 1: workers relay over a socketpair; mode 2:
   pool threads call directly since they're already inside
   `PROC_TCP_MAIN`) — so from OpenSSL's point of view `tcp_main_threads >
   0` is the same story either way: one process forks from the master,
   carries on using its own already-initialized OpenSSL state, and never
   contends with anyone else for it. Thread-locals simply persisting
   across that one fork is normal, known, supported OpenSSL behavior —
   it's *concurrent* post-fork use across separate processes that's
   unsafe, and mode 1 never does that. One separate, mode-independent
   wrinkle: `sipcapture`'s own MySQL-over-TLS `child_init()` runs in
   *every* child regardless of TCP mode (it's not part of the reactor
   trampoline scheme at all) — but that alone doesn't reproduce the
   failure below unless something else is *also* doing independent
   concurrent OpenSSL init in another process at the same time, which
   only mode 0 arranges.

   Default when `TLS_THREADS_MODE` is unset: `tls_threads_mode=0` — no
   protection at all. Per `src/modules/tls/OpenSSL3-README.md`,
   `tls_threads_mode=2` installs an OpenSSL `pthread_atfork()` handler
   that purges OpenSSL's thread-local state in each freshly-forked child
   — the documented fix for "OpenSSL TLS data corruption in shared
   memory by workers." Without it under mode 0: a real, reproducible
   failure — kamailio's TLS module hooks `CRYPTO_set_mem_functions()` so
   *all* OpenSSL allocations (from any process, for any purpose) route
   through kamailio's own shared-memory allocator; a crash or corruption
   during one child's concurrent OpenSSL init can wedge that shared
   allocator's lock permanently for the instance's whole life. Symptom:
   process alive, listening, port open — but **totally unresponsive to
   SIP and RPC**, forever, until restarted. `gdb -p <pid> -batch -ex
   'thread apply all bt'` on a stuck process shows a thread parked in
   `futex_get()` inside `qm_shm_malloc`/`qm_shm_free`, called via
   OpenSSL's `EVP_CIPHER_fetch`/`ERR_pop_to_mark` machinery from
   `sipcapture`'s (or any other independently-initializing child's) TLS
   setup. Hit rate observed: roughly 50%+ of cold starts under mode 0
   without this set. **Confirmed irrelevant for `tcp_main_threads > 0`**
   (mode 1/2): no `CRYPTO_set_mem_functions()`/pthread `PROCESS_SHARED`
   hooks are installed there at all, so this bug class structurally
   cannot occur regardless of `TLS_THREADS_MODE`.
   - **Set `TLS_THREADS_MODE=2` when testing mode 0. Not needed for mode
     1 or mode 2.**
   - **Always verify RPC responsiveness explicitly** (`kamctl rpc
     core.uptime`, short timeout, e.g. 10s) **after every restart**
     before trusting anything else — process count, `pgrep`, even a
     `"Listening on"` banner in the log do **not** prove the server is
     actually responsive. This wedge produces a server that looks fully
     alive by every process-level check while being completely deaf.

2. **Process count does not distinguish TCP threading mode.** The mode-2
   reactor pool is *threads* inside `PROC_TCP_MAIN`, not separate OS
   processes — `children=N` worker-process count is the same regardless
   of mode. Use `pidstat -t` (thread-level) or check thread names
   (`tcpr-iowait`, `tcpr-pool-N`, if `pthread_setname_np` is available —
   itself a CMake-only probe, see below) to actually confirm which mode
   is live.

3. **`pthread_setname_np`/`PTHREAD_MUTEX_ROBUST` are CMake-only probes**
   (`cmake/lock_methods.cmake`) with **zero legacy-Makefile equivalent**.
   Building via the old `make`-based system silently takes the graceful
   fallback the code already has for platforms lacking these (unnamed
   reactor pool threads; `tcp_cond.c`'s process-shared mutex is
   non-robust — a pool thread dying while holding it won't auto-recover
   via `EOWNERDEAD`, same accepted-elsewhere tier as macOS lacking the
   capability at all). No build error, no warning. To confirm which
   build produced a given binary: `nm <binary> | grep
   tcp_cond_recover_owner_dead` — present only if
   `HAVE_PTHREAD_MUTEX_ROBUST` was defined (CMake build).

4. **`journalctl --since`/`--until` wants the server's *local* time, not
   UTC** — even though the log lines themselves are timestamped plainly.
   A UTC-labeled window against a server in a different timezone (e.g.
   UTC+8) silently returns the wrong (often empty) results with no error
   — easily misread as "clean" when it's just the wrong window.

5. **Naive `grep -i oom` against journalctl/dmesg false-positives** on
   any random identifier that happens to contain the substring "oom" —
   e.g. a call-ID like `...LLc07toomtyvTG6vlb...`. Use a precise pattern
   (`oom-killer|out of memory|killed process`), not a bare substring
   match, when scanning logs for real OOM events.

6. **A site's own dev-tooling module lists can silently go stale**
   relative to the actual source tree — e.g. a hardcoded `MODULES` list
   in a build-helper script referencing a module that was renamed/removed
   upstream. The legacy `make -C src ... every-module` target aborts
   partway (`module not found`, `Error 1`) on the first stale entry,
   though `-j4` without `-k` usually means whatever was already launched
   in parallel still finishes — so a partial module set can look like a
   complete success at a glance. Check module output counts / specific
   `LD (gcc) [M <name>.so]` lines for anything you actually depend on
   before trusting a full-module-set build.

7. **`usrloc`'s `Tcpconn-Id` is process-local state, not durable.** It
   tracks which *live* TCP connection backs a registered contact —
   present even for plain (non-`;ob`) registrations — but a kamailio
   restart invalidates every `Tcpconn-Id` even if the usrloc *rows*
   persist (DB-backed usrloc, or a config that survives restart). A
   registration that looks fine in `kamctl ul show` can still be
   pointing at a connection that no longer exists process-wise. When
   testing anything connection-reuse-dependent, re-register (or at least
   re-verify `Tcpconn-Id` freshness) after any server restart — don't
   assume a pre-existing registration's tracked connection is still
   valid.

8. **`systemd-coredump`'s own storage quota is separate from real disk
   space** — "Cannot store coredump ... No space left on device" can fire
   with plenty of free space on `/` (confirmed: 11G free, 70% used, quota
   still exhausted). Check `df -h` to rule out genuine disk pressure
   before assuming that's the cause; the fix (raising
   `/etc/systemd/coredump.conf`'s size limits, or clearing old dumps in
   `/var/lib/systemd/coredump/`) is different from a real disk-space
   problem. Matters because a crash you need a core for might silently
   fail to produce one under this condition — don't assume "no coredump
   found" means "didn't crash."

9. **Client-side, not kamailio core: don't reach for classic sippy's
   `ElPeriodic`/`EventDispatcher2` when extending the Python test
   harness — it's solving a different problem than it looks like, and a
   heavier one than the harness needs.** `libElPeriodic` (Sobolev's C
   library, `sobomax/libelperiodic`) is not a competing timer-wheel or
   heap — checked directly (`src/prdic_main_pfd.c`): it's a **phase-locked
   loop** (`_prdic_PFD_get_error`, a real proportional phase/frequency
   detector) that drift-corrects a single periodic "tick" to hold a
   stable target frequency despite OS-scheduling jitter — almost
   certainly inherited from sippy's RTP/media-timing heritage (precise
   audio packetization), not from SIP transaction-timer needs. Classic
   sippy's own `dispatchTimers()` (the `elperiodic` branch/remote of the
   sippy fork) is, underneath the PLL tick, just a plain `heapq` of
   registered timers — the same fundamental structure asyncio/uvloop/
   trio already give you natively. SIP retransmission timers don't need
   PLL-grade frequency stability (a Timer A firing 5ms late is a
   non-event), so the PLL layer is real engineering solving a real
   problem, just not *this* one — cool math, wrong tool for a
   timeout-heavy SIP stack. The `EventDispatcher.py` this campaign
   actually runs (`client-test/libs/b2bua-TBS/sippy/Core/
   EventDispatcher.py`, docstring: *"Duck-cousin of
   sippy.Core.EventDispatcher.EventDispatcher"*) already reaches the
   right conclusion: it drops the PLL-tick layer entirely and makes each
   timer its own independent `anyio.sleep(secs)`-backed task
   (`tg.start_soon()`) — no wheel, no heap of its own, no phase
   correction, just handing "which timeout fires next" straight to
   whichever backend anyio is running on. Keep it that way when
   extending the harness; there's no need to reintroduce `ElPeriodic`-
   style tick machinery for timeout-heavy SIP client code.
