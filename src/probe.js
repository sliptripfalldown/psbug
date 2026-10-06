// Read-only kernel dump via the exploit's kernel-mediated pipe reads
// (userland memcpy on kernel VAs faults — supervisor pages). Chunk size
// is adaptive: start at 1MB, halve on short reads, so total ROP volume
// stays tiny regardless of what the forged pipe accepts.

const TOTAL = 4 * 1024 * 1024; // kernel text to capture
const MAX_CHUNK = 0x100000;    // 1MB
const MIN_CHUNK = 0x4000;      // 16KB floor (= stock pipe size)

async function postPart(name, bytes) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 20000);
  try {
    await fetch("/dump/" + name, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: new Blob([bytes], { type: "text/plain" }),
      signal: ctrl.signal,
    });
    return true;
  } catch (e) {
    log0("probe: POST failed (" + e + ") — skipped");
    return false;
  } finally {
    clearTimeout(timer);
  }
}

let log0 = () => {};

export async function dumpKernel(result, log) {
  log0 = log;
  const kern = result && result.kern;
  if (!kern || !result.kbase || !kern.kreadFast) {
    log("probe: no kernel context, skipping");
    return;
  }

  const p = kern.p;
  let chunk = MAX_CHUNK;
  const stem = "ktext_1360_0x" + result.kbase.toString(16);
  let ok = 0;
  let part = 0;

  for (let off = 0; off < TOTAL;) {
    const want = Math.min(chunk, TOTAL - off);
    const dst = kern.p.malloc(want, 1);
    let got = -1;
    try {
      got = await kern.kreadFast(result.kbase.add32(off), want, dst);
    } catch (e) {
      log("probe: read threw at +0x" + off.toString(16) + " (" + e + ") — stopping");
      break;
    }
    if (got !== want) {
      if (chunk > MIN_CHUNK) {
        chunk = Math.max(MIN_CHUNK, chunk >> 1);
        log("probe: short read (" + got + "), chunk -> 0x" + chunk.toString(16));
        continue;
      }
      log("probe: unreadable at +0x" + off.toString(16) + " — skipping page");
      off += want;
      continue;
    }

    log("probe: +0x" + off.toString(16) + " got 0x" + want.toString(16) + " — extract");
    const out = new Uint8Array(want);
    for (let j = 0; j < want; j += 4) {
      const v = p.read4(dst.add32(j));
      out[j] = v & 0xff;
      out[j + 1] = (v >>> 8) & 0xff;
      out[j + 2] = (v >>> 16) & 0xff;
      out[j + 3] = (v >>> 24) & 0xff;
    }
    log("probe: +0x" + off.toString(16) + " posting");
    if (await postPart(stem + "_part" + part + ".bin", out)) ok++;
    part++;
    off += want;
  }

  log("probe: done, " + ok + " parts (" + (chunk === MAX_CHUNK ? "1MB chunks" : "chunk 0x" + chunk.toString(16)) + ")", "info");
}
