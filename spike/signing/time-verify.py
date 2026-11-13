"""Wall-clock of a fresh `spikeverify` process (embedded trusted root, digest
passed as hex so artifact hashing is excluded). Usage:
  python3 -I time-verify.py <spikeverify> <bundle> <alg> <digest-hex> <extra args...>
"""
import statistics, subprocess, sys, time

exe, bundle, alg, dig, *extra = sys.argv[1:]
cmd = [exe, "-bundle", bundle, "-alg", alg, "-digest", dig, *extra]
ts = []
for i in range(21):
    t = time.perf_counter()
    r = subprocess.run(cmd, capture_output=True)
    ts.append((time.perf_counter() - t) * 1000)
    if r.returncode != 0:
        print(r.stdout.decode(), r.stderr.decode())
        sys.exit(1)
ts = ts[1:]  # drop first (page-cache warmup)
print("runs=%d median=%.1fms min=%.1fms max=%.1fms" % (len(ts), statistics.median(ts), min(ts), max(ts)))
