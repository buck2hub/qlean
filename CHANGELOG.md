# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `GuestOs` and `ImageConfig::guest_os` (default `GuestOs::Linux`) for describing the guest operating system family
- `ImageConfig::with_guest_os`, `Image::guest_os()` and `Machine::guest_os()` accessors
- Windows image validation: `GuestOs::Windows` requires `GuestArch::Amd64` plus an explicit `source` and `digest`
- Windows guests boot on OVMF UEFI firmware (`q35`, per-VM `ovmf_vars.fd` that survives restarts) and a per-VM TPM 2.0 device backed by `swtpm`
- Host prerequisite checks for Windows guests (KVM, OVMF, `swtpm`, `xorriso`) that report every missing prerequisite in one actionable error, with `QLEAN_OVMF_CODE`/`QLEAN_OVMF_VARS`/`QLEAN_SWTPM` overrides
- README Windows host setup with minimum/recommended VM resources
- Windows first-boot deployment: a per-VM seed medium (`QLEANSEED`) carrying the client public key, a randomly generated per-VM SSH host key and `deploy.json`, attached only on `init` and deleted once the guest writes its deploy marker
- `Machine::ssh_host_key` exposes the per-VM Windows host key so the transport can pin it instead of trusting the first key seen
- Windows deployment budget of 900s (`MachineConfig::ssh_timeout` overrides) with an actionable timeout error, independent of the Linux SSH connect timeout
- README "Windows image contract" describing the required first-boot task, account and ACL rules
- Windows SSH transport over the libvirt NAT network: the guest address is resolved from its DHCP lease on the host before connecting, so `Machine::get_ip` never runs inside a Windows guest
- Pinned host keys for Windows SSH sessions: the key presented by the guest must match the per-VM key generated at deploy time, and certificates are rejected; Linux guests keep vsock trust-on-first-use
- README "Windows transport and security" describing address discovery, host key pinning, the Linux-only vsock requirement and pool isolation
- Windows `exec` semantics: command strings are passed verbatim to PowerShell (the image contract now requires OpenSSH's `DefaultShell` to be PowerShell), and exit codes outside `0..=255` are reported as errors instead of being truncated
- Empty and whitespace-only `exec` commands are rejected with an actionable error before an SSH request is sent
- README "Windows command execution" documenting the verbatim command contract, stream separation and exit-code rules
- `src/guest_path.rs`: a single `GuestPath` conversion layer for every remote SFTP entry point, validating Windows drive paths, root spelling, separators, spaces, non-ASCII names, `..` traversal, invalid characters, reserved device names, and rejecting UNC/device namespaces
- Windows file semantics: `upload`/`download` round-trip files and directory trees, `copy` uses PowerShell `Copy-Item -LiteralPath` instead of the POSIX `cp`, `remove_dir_all` deletes recursively, and `hard_link`/`read_link`/`set_permissions` return explicit unsupported errors
- `Machine::get_ip` returns the transport address for Windows guests and, when it must be re-queried, runs PowerShell inside the guest and keeps only the address whose MAC matches that VM, erroring on a missing or ambiguous result instead of returning another VM's address

### Changed

- Cached image metadata records `guest_os`; legacy metadata without the field deserializes as `Linux`, and a cache entry recorded for a different guest OS is rejected with an actionable error
- Windows image cache entries use a `windows-` name prefix so they can never share a cache slot with a Linux image
- Windows guests reject TCG: a launch without KVM acceleration now fails with an actionable error instead of silently emulating
- A `secboot` OVMF code image paired with a vars template that carries no Microsoft keys (including via `QLEAN_OVMF_CODE`/`QLEAN_OVMF_VARS`) is now refused with an actionable error instead of booting in Secure Boot setup mode, which Windows 11 rejects
- `Machine::open_interactive_shell` returns an actionable error for `GuestOs::Windows` instead of attempting a vsock shell
- `is_running` no longer reports a live QEMU as stopped just because its control socket is missing: a live process without a socket is an error, so a second QEMU cannot be started on the same disk
- `with_pool` no longer requires `/dev/vhost-vsock`, and `with_machine` requires it only for `GuestOs::Linux`

### Fixed
- A command the guest killed with a signal was reported as a dropped connection: both SSH
  command loops ignored `exit-signal` - which a server sends *instead of* an exit status (RFC
  4254 section 6.10) - reached the end of the channel and answered "SSH channel closed before
  exit status", the same sentence a pulled cable produces. The error now names the signal,
  whether the guest dumped core and the guest's own message, so an OOM-killed deploy script or a
  `kill -9` typo reads as what it was.
- The Windows seed medium's stale copy was removed with `let _ = std::fs::remove_file(..)`, so a
  name taken by a directory (or a file that could not be unlinked) failed later as
  "failed to create the Windows seed ISO ... with owner-only permissions" - `EEXIST` blamed on
  its own permissions. A medium that cannot be replaced is now reported as exactly that; a
  medium that is simply absent is still a new medium.
- Two directories that receive secrets were created with the umask's permissions and then
  `chmod`ed: the Windows seed root (which receives the guest's SSH host private key) and the
  Windows run directory on the launch path (which receives the TPM state). Under `umask 000`
  that is a `0777` directory for as long as the `chmod` has not run. Both are created owner-only
  at creation time now, like the run directory and the TPM state directory already were, and the
  guard that enforces the rule reads these two call sites as well.
- `copy` decided whether its destination was a directory by "`if let Ok(meta) = ...`": a
  permission error on the parent, an expired session or a dropped connection all read as "not a
  directory", so the copy went ahead toward a destination that may well have been one — and on a
  Windows guest `Copy-Item -Destination <dir>` copies *into* the directory instead of replacing
  a file. The destination now answers through the same checked helper the upload and download
  use, so the three call sites cannot disagree about what a definite "nothing is there" is.
- `download` decided whether the local target was a directory by whether it could be stated:
  a permission error, a symlink loop, a path whose component is a file and a genuine I/O error
  all became "not a directory", and the transfer then wrote to (or failed against) the path as
  given. Only the answers the host filesystem defines as "there is no directory here" count as
  a no now; everything else is reported with the path it could not inspect.
- The owner-only credential write promised that a crash leaves "either the previous file or a
  complete one", but nothing was synced: the bytes only reached the page cache and the rename
  published the name anyway, so a power cut could leave a private key or a deploy seed that is
  complete by name, `0600` by mode, and empty or half-written by content. The staged file is
  synced before the rename and the directory after it, and a directory that cannot be flushed
  is reported instead of assumed durable.
- A TPM stopped from synchronous code (the `Drop` path, which runs when nothing else could)
  reported nothing: a child that outlived the grace was killed and the call returned as if it
  had left, so the run directory and the TPM state inside it were removed under a process that
  might still have held them. The synchronous stop now answers whether the exit was confirmed,
  keeps the same sentence as the asynchronous teardown when it was not, and warns about a
  `SIGKILL` nobody could reap.
- Whether an upload target was a directory was decided by whether it could be listed: an
  unreadable directory, an expired session or a server that answers `opendir` on a plain file
  with a generic status all came back as "not a directory", and the local file was then aimed
  at the directory's own path instead of inside it - on a Windows guest, `C:\out` where
  `C:\out\file.txt` was meant. Only the two statuses the protocol defines as "there is
  nothing here" count as that answer now; every other error says it could not find out, and
  names the path it was asking about.
- A TPM process whose exit could not be awaited was reported as stopped: a `wait` that itself
  fails (`ECHILD`, for example after the child was reaped elsewhere) used to take the same
  branch as a clean exit, so teardown carried on and the next start could rebuild the TPM state
  directory of a process that still held it. `Swtpm::stop` now answers whether the exit was
  confirmed, and the shared teardown warns that the directory is not vouched for when it was not
- Two machines that needed the same image at the same time shared one staging file for it
  (`<image>.part`, named after the destination alone): the second one truncated the file the
  first was streaming into, and because each checksum is computed over its own stream rather
  than over the file, the promoted image could hold bytes nobody verified - and a file that
  had already been moved into the cache could keep growing while QEMU read it. The staged file
  is now locked while it is written, and a second writer is told which file is already being
  written instead of corrupting it.
- Two pooled machines initializing at the same time staged their SSH key in one temporary
  file: the name came from the destination alone, so the second write removed the first one's
  staging file and the first then renamed the second writer's bytes into place. The installed
  key could be one a machine never wrote, or a half-written one, and the other start failed
  with an error about a temporary file that no longer existed. Each write now stages its bytes
  in a temporary file of its own.
- A rejected image whose removal failed was reported as removed: the digest mismatch said
  "the file was removed" no matter what the unlink did, so a read-only cache directory or a
  full disk left the corrupt image behind exactly where a later run would pick it up. The
  message now says the file is still on disk, names the path and asks for the delete.
- A start could adopt the pid of a QEMU that had already died: the pid file was read back
  before the new QEMU wrote it, so a run directory that outlived a killed Qlean process (or
  was restored from a copy) made the machine record a foreign pid. Every later signal step
  then reported "nothing left to kill" while the running guest kept the overlay open. The
  pid file is now removed before QEMU is spawned, and a file that cannot be removed fails the
  launch instead of being started over.
- A pool operation that failed reported only the outermost reason, so the machine's name
  arrived without the cause it was wrapped around: `init_all`, `spawn_all` and `shutdown_all`
  said `alpha: failed to ask the QMP socket whether the machine was running` and dropped the
  socket path that refused the connection. The machine name is now a context layer and the
  combined message renders the whole chain.
- A transfer that failed while flushing or closing was reported as successful: both
  `upload_file` and `download_file` discarded those errors, and a receiving file reports
  success while the data is still buffered, so a full disk showed up as a complete upload or a
  download with a missing tail. The end of the copy is now part of the copy, and the error
  names the file. `Machine::write` also left the guest holding the file open - the SFTP handle
  from `create` was dropped, not closed - which on Windows denies the rename and delete that
  the next call performs.
- The reserved Windows device names were missing the console devices, so `CONIN$`,
  `CONOUT$` and `CLOCK$` were accepted as ordinary file names: SFTP then opened the console
  instead of a file, or failed with a message about a device nobody asked for. Windows guest
  paths now refuse them, like `CON` and `NUL`.
- Uploading a directory to a Windows guest quietly reshaped the tree when a local entry name
  contained a backslash: `a\b` was sent as `a/b`, so the file landed in a directory that may
  not have existed, and an entry really named `b` in `a` was overwritten. A name is not a
  path, so the entry is now refused by name, and the error says to rename it.
- Allocating a guest CID panicked in a debug build and wrapped to a reserved value in a
  release build when a run directory already recorded the highest CID a guest may use: the
  next machine either crashed the library or was booted with an address the host cannot
  dial. The allocation now refuses, names the offending run directory and says which
  directories to remove.
- A backslash in a guest path was folded into `/` for every guest, so on a Linux guest `a\b` (a legal name) was addressed as `a/b` - a different file - and `a\..\b` made the whole walk fail; a backslash separates only on Windows, and a Linux guest keeps it as an ordinary character in a name
- Uploading a tree approximated a name that is not valid UTF-8 instead of refusing it: every such byte became `U+FFFD`, so two entries differing only in that byte arrived as one guest name and the second upload silently overwrote the first; an entry whose name has no guest spelling is now refused by name, since a guest path is a UTF-8 string
- `upload` of a path that is itself a symbolic link followed it: the local path was classified with a following `stat`, so the bytes sent were the target's and, on a Windows guest, the rule that refuses links never ran because that branch was never reached. The root is now classified from the entry's own attributes and both the root link and a link inside a tree go through one shared transfer that refuses it on Windows and recreates it on Linux
- `download` of a path that is itself a symbolic link followed it: the remote path was classified with a plain `stat`, so a link to a regular file looked like a file, the open followed the link, and the copy held the target's bytes with no error - the one place a link could still be followed after the walk learned not to. The root is now classified from the entry's own attributes and a link is refused by name
- Downloading a tree followed symbolic links while walking it: the walk asked for each entry's target attributes, so a link to a directory was copied as a directory (its contents folded into the local tree instead of the documented error naming the link) and a broken link could not be classified at all, which also made `remove_dir_all` unable to remove a tree that contained one. The walk now asks for the entry's own attributes

- Downloading a tree logged an entry it could not read or stat at debug level and skipped it, so a broken symlink or a directory the guest would not list came back as a successful, incomplete copy; the walk now fails with the path and the walk root

- Uploading a directory tree that contains a symbolic link to a Linux guest created the link at the *target's* path: `SSH_FXP_SYMLINK` carries two strings, the client fills the draft's `linkpath` field first, and OpenSSH reads the first string as the link's target. A link whose target was writable was silently created in the wrong place, and one whose target already existed failed with "failed to recreate the symbolic link". The request is now sent in the order OpenSSH reads it, from `ssh::symlink_arguments`

- Windows guests no longer lose the reason Secure Boot was skipped: when the host
  has a `secboot` OVMF code image but no Microsoft-enrolled vars template, Qlean falls
  back to a plain code image and now warns with the skipped pair and the Windows 11
  Secure Boot requirement instead of staying silent. The README no longer claims that
  such a pair makes Qlean refuse to start.

- DHCP lease lookup took the first row matching the MAC, so after a renewal it dialled the address the guest had already abandoned; the row with the newest expiry now wins, and the timeout error shows each lease's expiry
- Waiting for the Windows deployment marker treated a dropped session as "not deployed yet" and burned the whole 900s budget
- `MachinePool::init_all` failed on a Windows machine that had already deployed, and `spawn_all` booted a Windows guest before its deployment
- `Drop`, `shutdown` and the failed-launch cleanup sent signals to whatever process held the recorded pid; if QEMU had already exited and the pid was reused, an unrelated process was killed, and a pid reused by *another* QEMU still passed the first fix because every QEMU names itself the same way. The pid is now verified against `/proc/<pid>/cmdline` before any signal is sent: argv[0] must be `qemu-system*`/`qemu-kvm` **and** the command line must carry this machine's own QMP socket, so a guest belonging to the user or to another checkout is left alone
- A launch that failed after QEMU started left `swtpm` and the pid behind, and a panicked SSH task detached QEMU entirely
- Windows DHCP lookup returned the first lease for a MAC, so a dual-stack network could hand a link-local IPv6 address that cannot be dialled
- `GuestPath::join` accepted an absolute child and silently made it relative on Linux, and reported `\\?\` device paths as UNC
- Host paths embedded in a comma-separated QEMU option (`-drive file=`, `-chardev path=`, the OVMF images and the `swtpm` socket) were interpolated verbatim, so a directory name containing a comma was read as extra key=value pairs instead of a file name; such paths now fail with an actionable error before QEMU starts
- Windows first-boot address discovery ran before the QEMU liveness check, so a VM that died right after starting waited out the whole deployment budget and blamed a missing DHCP lease
- Recursive directory creation tried to create (and stat) a Windows drive root such as `C:`, which is drive-relative and can fail
- A failed `init`/`spawn` left the cancel token behind, so retrying on the same `Machine` reported "already initialized"/"already spawned" for a VM that never started
- `Machine::copy` wrapped `Copy-Item` in `powershell -Command "..."` inside an already-PowerShell shell, so `$` in a Windows path was expanded and the copy silently targeted a different file
- The Windows host prerequisite check omitted `xorriso`, so a host without it passed the check and failed later while staging the seed medium
- Secure Boot paired a `secboot` code image with the plain (empty-key) vars template, which boots in setup mode; the Microsoft-enrolled `.ms`/`.secboot` templates are now preferred
- Windows guests were launched with `vhost-vsock-pci`, so a Windows VM needed `/dev/vhost-vsock` and the `vhost_vsock` module and failed to start without them; the device is now added only for Linux guests
- OVMF setup required the code image and vars template to be exactly the same size, which no stock firmware pair satisfies (a ~528 KiB vars template ships next to a multi-megabyte code image); only a vars template larger than the code image is now rejected
- The `swtpm` control socket was created with default permissions; it is now owner-only (`mode=0600`)
- DHCP leases are matched by the MAC address itself, so a dashed MAC column or an
  uppercase query still finds the lease instead of reporting that no lease ever appeared
- `MachineConfig` rejects values that cannot describe a machine (zero cores, zero memory, a
  0 GB disk, a zero `ssh_timeout`) by field name before anything is written to disk, instead
  of letting QEMU report it later as "QEMU exited unexpectedly"
- A digest of the wrong length (`sha256:` with anything but 64 hex characters) is rejected as the typo it is instead of being reported later as a mismatching image
- The `User-Agent` sent when downloading a guest image follows the crate version instead of a hand-written `0.3.0`
- A failing `virsh net-list` is reported as libvirt being unreachable instead of being read as "the qlean network does not exist"; libvirt's own message is surfaced when defining or starting the network fails
- Closing the guest SSH session is bounded too (5s): a guest that stopped answering no longer blocks shutdown before the kill fallback
- QMP exchanges are bounded (10s), so a wedged QEMU makes shutdown fall back to killing it instead of hanging a test forever
- Shutdown recognises a killed-but-unreaped QEMU as gone instead of waiting out the whole teardown budget on a zombie `/proc` entry and then reporting a misleading force kill
- Qlean's own guest commands (address query, file copy) run through `powershell -EncodedCommand` and no longer need a specific OpenSSH `DefaultShell` in the image
- `with_machine`/`with_pool` keep a closure's own failure as the primary error and attach a teardown failure to it, instead of replacing the reason a test failed
- The deployment-marker probe quotes the marker path, so a path with a space cannot be read as "file not found" and make a finished deployment look unfinished for the whole budget
- A local image whose file name is not valid UTF-8 gets its own cache entry instead of sharing `custom-image` with every other such image and being re-downloaded on every switch
- A Windows first boot spends one deployment budget across the DHCP lease wait, the `sshd` wait and the deploy-marker wait, matching the documented contract; a spent budget names the phase that never ran
- A Windows guest that completes the handshake and rejects Qlean's key now reports that at the end of the budget, naming the authorized_keys install location, the ACL, and the blank-password trap (`LimitBlankPasswordUse`) instead of a generic "not reachable"
- During a Windows first boot a host key that is not the deployed one is retried until the deploy budget is spent and then reported as exactly that; after deployment a mismatch stays fatal
- A pre-existing `qlean` libvirt network is checked against Qlean's `qlbr0` bridge before startup: a stale definition with another bridge now fails with the exact recreate commands instead of a QEMU bridge error and a guest that never gets a lease
- Qlean's own guest probes (deploy marker, address query, file copy) run under a bounded budget, so a wedged SSH channel fails with an honest message instead of hanging past the deployment budget. User commands stay unbounded: a silent `sleep 600` is not a wedged channel
- The Windows guest address is chosen from IPv4 only, at the selection site as well as in the parser: a dual-stack adapter's link-local IPv6 row can no longer be dialled, nor make a single usable IPv4 address look ambiguous
- Cleaning up the Windows seed medium after a successful deployment is idempotent and no longer fatal: a half-finished cleanup (the guest rebooted between attempts) used to turn a successful first boot into an error, and a seed file that cannot be unlinked is now reported instead of failing a machine that is already deployed
- A failed launch can no longer hang: waiting for the QEMU task is bounded and abandons it, so the original failure (the boot log and the SSH error) is always what the user sees, and the SIGTERM sent during that cleanup goes through `kill(2)` with its refusal reported
- Teardown no longer claims a shutdown it cannot verify: a SIGKILL that the guest survives now fails with the pid to clean up instead of returning success, a `system-powerdown` that could not be requested is reported at `warn!` rather than `debug!`, and the force kill goes through `kill(2)` and reports whether the signal was actually delivered
- A QEMU that refused to start was reported as `exited with status 1; check its log`, so the reason (a missing firmware file, an unavailable `/dev/kvm`, a bridge ACL denial) stayed in a log the caller does not read. The last stderr lines QEMU printed now travel with the error, bounded to 10 lines of 400 characters, and the "check its log" wording is only used when QEMU said nothing
- A pool shutdown whose liveness probe failed treated the machine as stopped and left the QEMU process to be killed whenever the pool was dropped; an unanswerable QMP socket is what a *hung* QEMU looks like, and that machine is now shut down (with the probe failure named) instead of skipped
- `is_running` answered "no" for a live QEMU whose guest had stopped: `query-status` reports `running=false` for a paused guest and for the `io-error`/`internal-error`/`guest-panicked`/`watchdog` run states, so a second QEMU could be started on a disk another process still had open. Only the `shutdown` run state now means "not running"
- A local image source that was the cache destination (the same path, or a hard link to it) had the destination opened for writing before the source was read, so the copy destroyed the very image it was about to copy and verification then rejected the empty result. Such a copy is refused before anything is written, and a local copy is installed through a `.part` file exactly like a download
- A bounded program that was still running when its budget expired was reported as killed without anyone checking: the child is now killed and, if it is still there a second later, the error names the pid to clean up instead of claiming success
- A Windows image that was not qcow2 (a raw file, VHDX, VMDK) failed inside `qemu-img create` with `Image is not in qcow2 format` — after the whole image had been copied into the cache — without saying that qcow2 is the requirement or how to convert. The magic bytes are now checked before a local copy and after a download, and the refusal names the observed bytes and the `qemu-img convert -O qcow2` command
- `qemu-bridge-helper` is part of the host prerequisites: QEMU execs it (from `libexec`, so not on `PATH`) to attach a VM to the `qlbr0` bridge, and its absence is now reported together with the other missing host programs, including the `/etc/qemu/bridge.conf` allowlist that breaks bridging even when the binary exists
- `MachinePool::init_all`/`spawn_all` short-circuited on the first failure, which dropped the other machines' start futures mid-launch: a QEMU process could be left running with no pid recorded on the machine, so the next start would rebuild the overlay under a live guest. Every machine is now started and each failure is reported by name
- Firmware resolution stopped at the first *present* OVMF pair instead of the first *usable* one: a host whose distro ships `OVMF_CODE.secboot.4m.fd` next to the plain `OVMF_VARS.4m.fd` was refused outright, even though a non-Secure-Boot code image next to it would have worked. Unusable pairs are now skipped with the reason kept, resolution falls through to the next layout, and the failure lists every skipped pair plus the override
- QEMU's exit was misreported in both directions: a guest stopped by Qlean's own teardown (SIGTERM, then SIGKILL when Windows ignores ACPI powerdown) was reported as a launch failure, and `ExitStatus::code()` is `None` for a signal death, so the message read "QEMU exited with error code: None". A requested stop is now logged with the signal name and an unexpected death says `was killed by signal 9 (SIGKILL)` or `exited with status 3`
- A rejected pinned host key was retried like a refused connection: `connect_ssh` and `connect_ssh_windows` treated the security decision as transient, spent the whole connect budget on it and then reported the guest as unreachable. Both loops now return the rejection immediately; detection and construction share one phrase so they cannot drift
- Three user-facing messages carried a run of spaces in the middle of a sentence (left over from a lost line continuation), and a test now rejects that shape in the Windows-facing messages
- `Machine::spawn` accepted a Windows guest whose deployment had never run: `spawn` boots without the seed medium, so the guest could never install the SSH key and the only symptom was a deployment wait that timed out 15 minutes later. Only `MachinePool` knew to route this case to `init`; the public entry point now refuses it with the fix in the message
- Two "cannot tell" answers were reported as "no": probing the Windows deployment marker without an SSH session returned `Ok(false)`, so a lost session made `init` poll for the whole 15-minute budget and then blame the guest, and `is_running` folded a failed QMP query into `false`, which tells the pool that launching another QEMU is safe. Both now report the problem, and `is_running` only concludes "not running" from a missing QMP socket
- The software TPM was always `SIGKILL`ed: `swtpm` writes its state while shutting down, so a killed process could leave a half-written state file and the guest then loses the TPM identity it sealed secrets against (on Windows, BitLocker recovery). Shutdown now sends `SIGTERM`, waits two seconds and only then kills; the synchronous `Drop` path waits the same way instead of leaving `kill_on_drop` to `SIGKILL` the child immediately after the signal
- The per-VM OVMF vars image was trusted blindly: a copy of a read-only (`0444`) vars template left QEMU unable to write the firmware variables back, and a vars image left over from an older OVMF build (or a truncated one) was reused without a size check. The copy is now `0600` and writable, and a reused image whose size differs from the template is refused with an explicit recovery step instead of being booted or silently reset
- Library entry points panicked where they could report a problem: `QleanDirs::new` used `expect` when `XDG_DATA_HOME`/`HOME` is unusable (including inside `Drop for Machine`, where a panic while unwinding aborts the process), `create_dir` used `expect` on a directory it could not create, and `launch` still had two `expect`s of its own; all of them now return errors that name the cause
- A `Machine::new` that failed halfway (missing `qemu-img`, missing OVMF, `swtpm` or a failing `xorriso`) left the run directory, the disk overlay and the staged seed behind, because no `Machine` existed to clean up; the run directory is now removed when construction fails, and a Windows host is checked for KVM/OVMF/`swtpm` before any key or seed material is generated
- Host paths passed to `xorriso` went through `to_string_lossy`/`to_str().unwrap()`, so a home directory that is not valid UTF-8 produced either a panic or a silently different path; the `key=path` arguments are now built as `OsString`s and keep the exact bytes
- A download that ended early was renamed into the cache and then reported as a *checksum* mismatch, which points at the wrong cause; the received byte count is now compared with the advertised length before the file is promoted, and a rejected image is deleted instead of being left behind in the cache directory
- The host prerequisite check stopped at the first missing program, so a fresh host needed one install-and-retry round per tool; the four CLI programs are now probed in one pass and reported together, and a program that exists but cannot run `--version` is reported as a broken installation instead of a missing one
- Qlean's directories were created with the host umask, and the built Windows seed medium (which carries the per-VM host private key) was world-readable: data/secrets/runs, each run directory and the seed directory are now `0700`, and the seed medium is `0600` until it is deleted
- A failed Windows first-boot deployment left the VM running with the seed medium (client public key and per-VM host private key) still attached; the launch path now closes the session, terminates QEMU, stops `swtpm` and clears the endpoint state
- A launch whose QEMU pid file could never be read now stops `swtpm` and waits a bounded time instead of returning while the TPM and a half-started VM remain
- A second `init` on an already-deployed Windows machine is rejected with an actionable error (use `spawn`), instead of booting without the consumed seed medium
- Windows first boot waited only for the 180s/300s Linux connect budget before giving up on `sshd`, so the 900s deployment budget could never be reached; `init` now waits within the deployment budget and later boots keep the connect budget
- `Machine::exec` reported every non-zero exit code as success: the SSH exit status was passed to `ExitStatus::from_raw` as if it were a wait status, so `status.code()` always returned `0`. Exit codes are now converted correctly, which is a behavior change for callers that relied on the previous (incorrect) `status.success()` result
- Operations that need a live guest (`exec`, `upload`, `download`, `remove_dir_all` and the file helpers) panicked on an internal `expect` when the machine was not running, while `exec` alone returned `SSH session not established`; they now share one actionable error that names the operation and how to start the machine
- Symbolic links are no longer skipped silently during `upload`/`download`: recreating a link that fails, or meeting a link that cannot be transferred, is now an error
- Building the Windows seed ISO ran `xorriso` without a deadline, so a stuck build (an unreachable network mount under the staging directory, a hung FUSE mount) blocked `Machine::init` forever before the first-boot deadline had even started; the build now has a 120s budget and the child process is killed at the deadline with an error that names `xorriso` and the staging directory assumption
- A lease that never expires (`infinite`) was parsed as "no expiry", so it ranked below every expiring row and the lookup could return an address the guest had already abandoned; it now outranks real timestamps, while a row with an unrecognizable expiry still ranks lowest
- Teardown's "still running after SIGKILL" error carried a 30-space hole where a line continuation was intended, and the guard that rejects padded user-facing messages did not cover it; the message is now one sentence and is part of that guard
- A DHCP lease lookup where `virsh net-dhcp-leases` never succeeded was reported as "the guest may still be booting", so an unreachable or unreadable libvirt sent the reader to the wrong machine after the full budget; the timeout now says the lease table could not be read, keeps `virsh`'s own message, and only speculates about the guest when a listing actually succeeded
- Each `virsh net-dhcp-leases` call in the lease poll is now capped by what is left of the lookup budget, so a wedged libvirtd can no longer outlive the deadline by hanging inside one call; the bounded-run helper is shared with the seed ISO build instead of existing twice
- Every external command on the launch, network and prerequisite paths (`qemu-img`, `xorriso`, all `virsh` calls, `--version` probes) is now bounded and killed at its budget, so a wedged host tool fails the launch instead of hanging it; a source guard keeps new unbounded `.output().await` calls out
- A prerequisite that hangs is now reported as installed-but-blocked instead of missing, so the advice that comes with a failed probe matches what actually went wrong

### Migration

- `ImageConfig` gained a public field, so struct-literal construction must add `guest_os` or `..ImageConfig::default()`; builder chains and `ImageConfig::default()` behavior are unchanged (source-breaking `0.4.0` minor, see README Migration)

## [0.3.1] - 2026-07-28

### Added

- `InteractiveShell` API for dedicated vsock SSH+PTY interactive shells via `Machine::open_interactive_shell`
- `InteractiveShell::write`, `read_chunk`, `resize`, and `close` for bidirectional terminal I/O without blocking management SSH
- `InteractiveShell::split` into `InteractiveShellReader` / `InteractiveShellWriter` for concurrent PTY I/O (e.g. `tokio::select!`)


## [0.3.0] - 2026-07-01

### Changed

- SSH connectivity uses vhost-vsock only (no TCP fallback)

## [0.2.3] - 2026-02-12

### Added

- Multi-distro image support, custom image handling, and streaming hash computation

### Documentation

- Enhance README with multi-distro and custom image info
- Fix docs error

## [0.2.2] - 2026-01-31

### Fixed

- Use `qemu:///system` URI to enable bridge creation for proper network setup

## [0.2.1] - 2026-01-29

### Added

- Fallback to TCG (Tiny Code Generator) when KVM is unavailable, enabling execution on systems without hardware virtualization support

[Unreleased]: https://github.com/buck2hub/qlean/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/buck2hub/qlean/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/buck2hub/qlean/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/buck2hub/qlean/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/buck2hub/qlean/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/buck2hub/qlean/releases/tag/v0.2.1
