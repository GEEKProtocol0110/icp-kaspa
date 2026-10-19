# Recovery signer and supervised TN10 watcher

This deployment kit separates the protected-v1 recovery key from the watcher.
It has offline protocol, subprocess and restart tests. **It has not been deployed
on independent hosts.** The funded pilot used one host; its proof remains separate.
No service is installed or left running by these source changes.

## Boundary and access

Use two independent Linux hosts with administrator-controlled software and public
configuration. The watcher account holds an SSH authentication key, public v1
artifacts, its approval database and signed outbox. The signer account holds only
the recovery role key. Keep owner, recipient and cold keys off both accounts;
keep the cold key on a separately controlled device. Do not copy the private pilot
archive onto the watcher. Testnet keys only.

The SSH account is restricted by a root-owned forced command. It accepts either:

- Recovery: `{"protocol":"icp-recovery-ssh-v1","descriptor_sha256":"…","pending":"TXID:0"}`.
- Readiness: `{"protocol":"icp-recovery-ssh-health-v1","descriptor_sha256":"…"}`.

One request per connection, maximum 1,024 bytes, EOF required. Other fields,
commands, paths, stages, destinations and policy pins are rejected. The server
independently checks a healthy, indexed TN10 node, the pinned descriptor, and an
exact live pending outpoint. It invokes only `prepare-recover` with the recovery
key; descriptor/status subprocesses receive no key. Native code rebuilds the
fixed quarantine transaction and verifies its script. The server validates its
shape and returns a prepared receipt without internal paths or node metadata.
It never broadcasts. The endpoint logs prepared transaction IDs, readiness and
generic refusal events to local authpriv syslog (`icp-recovery`), without payloads
or key paths. Ensure the host retains those logs. A readiness check verifies transport, policy and node health;
it does not load the private key or prove that a future signature will succeed.

The watcher checks the response against the exact expected input, quarantine
script, amount and fee cap, commits the signed payload to SQLite, then broadcasts
through its own public-only native process. An ambiguous broadcast is reconciled
against the chain before retrying the saved bytes. SSH failure never falls back
to local signing. Existing bounds of three attempts and ten seconds between
attempts remain. Preparing twice after a lost signer response can create different
signatures for the same recovery; only one can spend the exact outpoint.

A compromised watcher/SSH key can request quarantine for any pending output under
this policy, including an approved withdrawal. This is an availability attack;
the remote signer does not know operator intent. It cannot select a recipient,
release quarantine, sign an idle recovery through this interface, or access the
cold key. A compromised signer host can use its recovery key outside this API.
SSH and systemd are operational boundaries, not hardware isolation or an audit.

## Build and verify public state

Build the same reviewed source revision on each machine:

```sh
cargo build --locked --release --features live --bin icp-protected
cargo fmt --check
cargo test --locked --features live
python3 -m unittest discover -s tests -p 'test_*.py'
```

Install the source and release binary into `/opt/icp`, owned by root and not
writable by either service account. Compile the exact public policy into a
staging directory using the existing `setup` workflow. Install only
`public-policy.json`, `idle.json`, `pending.json`, and `quarantined.json` into
`/etc/icp/protected`, root-owned and readable by the respective account. Do not
run setup under a service account or recompile in place while monitoring funds.
The state paths must contain the same independently verified public artifacts.

Compute the descriptor pin independently on BOTH hosts, with no signing key:

```sh
ICP_PROTECTED_STATE_DIR=/etc/icp/protected /opt/icp/target/release/icp-protected descriptor > /tmp/icp-descriptor.json
python3 -c 'import hashlib,json; print(hashlib.sha256(json.dumps(json.load(open("/tmp/icp-descriptor.json")),sort_keys=True).encode()).hexdigest())'
```

Compare descriptor contents and the digest over a trusted channel. Put the digest
into both JSON configs; it must also match the descriptor already pinned into the
watcher's database. Public fixture policies use known keys: never fund them.

`ICP_PROTECTED_RECEIPT_DIR` moves native receipts out of the public state directory.
The deployment templates use private `/var/lib` directories, allowing public
policy/artifacts to remain read-only. Receipts, outboxes and SQLite contain signed
transactions and operational history; mode 0700 directories and umask 0077 apply.

## Signer host

Create a dedicated `icp-recovery` user with a locked password, `/bin/sh` shell and
root-owned home. Install the example signer JSON as
`/etc/icp-recovery/signer.json`; replace its digest and RPC URL. Prefer a local,
indexed, synced TN10 node; the native gate verifies the actual network identity.
Install the matching recovery role file as `/etc/icp-recovery/key.json`, owned by
`icp-recovery`, mode 0600, inside a root-owned directory traversable only by that
group. The public policy must bind that role's public key. Do not reuse the known
public fixture key. Create `/var/lib/icp-recovery/receipts` owned by that account,
mode 0700. The account cannot write the signer config, wrapper, source, binary,
public artifacts, home or authorized keys.

Install `deploy/icp-recovery-command` to `/usr/local/libexec/`, root-owned 0755.
Install `deploy/sshd-recovery.conf` in the host's sshd configuration. Review the
existing SSH policy, `AcceptEnv`, `PermitUserEnvironment`, included files and Match
blocks: this account must not acquire an alternative command or writable startup
script. Disable `PermitUserEnvironment` globally. Never accept `ENV`, `BASH_ENV`,
`PYTHONPATH`, `PYTHONHOME` or loader variables from SSH clients. Validate with
`sshd -t` and inspect effective account settings with `sshd -T -C user=icp-recovery,host=SIGNER_HOST,addr=WATCHER_IP`
before reloading SSH through the host's normal administrator procedure.

Put only the watcher's dedicated public SSH key in
`/etc/icp-recovery/authorized_keys`, root-owned. Restrict its source address and
forwarding, for example:

```text
restrict,from="WATCHER_IP" ssh-ed25519 REPLACE_WITH_WATCHER_PUBLIC_KEY icp-watchtower
```

The client sends no remote command; sshd supplies the fixed wrapper. Shell,
subsystems, PTY, forwarding and user RC are disallowed. The wrapper clears the
environment and kills a request after 90 seconds. Apply host firewall rules to
limit SSH to the watcher and administrator addresses. Limit concurrent/rate abuse
at the SSH/firewall layer; MaxSessions alone is not a per-user connection limit.
Restrict service account egress to its RPC node. Keep encrypted recovery-key
backups and a separately verified restoration procedure.

## Watcher host

Create a distinct `icp-watchtower` user and private
`/var/lib/icp-watchtower` directory. Install the example remote config as
`/etc/icp-watchtower/signer.json`, root-owned, readable by this account. Replace
host, port, username and digest. Install a dedicated SSH identity file readable
only by the watcher. **Obtain and verify the signer's host public key through an
independent trusted channel.** Place it in the configured known_hosts file using
OpenSSH host/port syntax (`[hostname]:port` for a nonstandard port). The client
requires that pin and ignores SSH agents, user configuration, global hosts and
trust-on-first-use. It will fail on a changed/unknown key. Do not use an unchecked
`ssh-keyscan` result as verification.

With the watcher stopped, arm a fresh v1 database for exact new idle deposits
using the existing arming workflow and `/etc/icp/protected` public state. Use
`--db /var/lib/icp-watchtower/watch.sqlite` and a temporary writable `--config`
path. Install the resulting descriptor root-owned at `/etc/icp/watchtower.json`.
Verify its digest matches both hosts. Do not bootstrap from already spent outputs,
reuse a v0 database, rerun the completed pilot, or invent an anchor for old funds.
Back up approvals through SQLite's backup API before operational changes.

A manual readiness check, as the watcher account:

```sh
cd /opt/icp
python3 -c 'import sys; sys.path.insert(0,"scripts"); import json; from recovery_signer import RemoteNative; n=RemoteNative(["/opt/icp/target/release/icp-protected"],"/etc/icp-watchtower/signer.json",json.load(open("/etc/icp/watchtower.json"))); n.probe(); print("Signer transport, descriptor and node ready")'
```

Run the watcher once in dry-run mode with the remote signer configured, inspect
its chain cursor and candidates, then install the supplied watcher, health and signer-probe units/timers into `/etc/systemd/system`. Replace the RPC URL in the watcher unit if
needed. As administrator, after reviewing the exact armed roots and config:

```sh
systemctl daemon-reload
systemctl enable --now icp-watchtower.service icp-watchtower-health.timer icp-signer-probe.timer
systemctl status icp-watchtower.service icp-watchtower-health.timer icp-signer-probe.timer
journalctl -u icp-watchtower.service -u icp-watchtower-health.service -u icp-signer-probe.service
```

The watcher unit uses a dedicated writable StateDirectory, read-only system and
public configuration, no inherited signer key/agent, and bounded failure restarts.
Five failures in five minutes stop restarts for operator reconciliation. Health
checks continue independently after the watcher stops. Do not reset retry counts,
change approvals or delete the database to make a red status disappear.

## Health, alerts and acceptance

`watch_health.py --db PATH` reads SQLite without creating a missing database and
returns JSON plus exit 0/1. It never emits signed payloads or private paths.
Checks include: unarmed state, missing/stale scan heartbeat (15 seconds), node DAA
not advancing (30 seconds), dry-run/local signing, failed/stale remote readiness
(probed every 30 seconds; stale after 120), last watcher error, unresolved recovery,
retry exhaustion, normal-delay deadline reached, and unauthorized execution.
The heartbeat retains the actual scan timestamp before slow signing/RPC calls;
restarts preserve DAA-progress history. A pending recovery remains unhealthy until
accepted-chain confirmation. Quarantine confirmation ends this watcher's custody
tracking; it does not monitor later cold release.

The health timer checks every five seconds and logs failures to journald. The
separate signer-probe timer has a bounded 40-second SSH request; it never blocks
the chain-monitoring loop. Without this probe timer remote readiness stays red. **This
is local monitoring, not external alert delivery.** Connect these JSON results
and failed units to an independently hosted monitor and an operator-approved alert
destination. No messages are sent by this kit. Keep a remote dead-man check for
host outage; a timer on the failed host cannot alert on its own power loss.

DAA units are not wall-clock seconds. These thresholds and the 90-second signer
request deadline do not guarantee recovery inside a 600-DAA delay. RPC delay,
backlog, stalled nodes, inadequate fees, monitoring latency and inclusion races
can exhaust the window. Tune health thresholds against measured host/node latency
and the actual immutable delay; do not automatically retry around hard errors.

Before calling independent hosting complete, record both hosts' identities and
software revisions, independently verified SSH/descriptor pins, account/filesystem
permissions, readiness, wrong-pin rejection, restart/outbox recovery, blocked RPC,
signer outage, missing/stale heartbeat, retry-exhaustion alerts and a separately
journaled fresh TN10 recovery with accepted-chain confirmation from another node.
Exercise alert receipt at the intended human destination. None of that deployment
or live acceptance is claimed by the offline suite.

Stop and reconcile on a deep reorg/pruned scan, database corruption, exhausted
attempts, unknown broadcast or immutable-policy drift. Keep WAL-aware backups and
disk monitoring; audit/block history has no automatic retention policy. Cold-stage
rescue, rotation and lost-key procedures remain separate work. No mainnet, quantum
safety or independent security audit claim is made.
