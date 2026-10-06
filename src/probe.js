// Read-only kernel dump: one ROP memcpy per 64KB part, stage-logged so a
// hang names its stage. POSTs are same-origin with a timeout; a failed
// part is skipped, not fatal.

const BATCH = 0x10000; // 64KB per memcpy call
const PARTS = 64;      // 4MB total kernel text
const LC_MEMCPY = 0x3e00; // window.SYMBOLS.libc.memcpy, libSceLibcInternal

async function postPart(name, bytes) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15000);
  try {
    await fetch("/dump/" + name, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: new Blob([bytes], { type: "text/plain" }),
      signal: ctrl.signal,
    });
    return true;
  } catch (e) {
    log0("probe: part POST failed (" + e + ") — skipped");
    return false;
  } finally {
    clearTimeout(timer);
  }
}

let log0 = () => {};

export async function dumpKernel(result, log) {
  log0 = log;
  const kern = result && result.kern;
  if (!kern || !result.kbase || !kern.chain) {
    log("probe: no kernel context, skipping");
    return;
  }

  const p = kern.p;
  const memcpy = p.libSceLibcInternalBase.add32(LC_MEMCPY);
  log("probe: allocating");
  const dst = p.malloc(BATCH, 1);
  const out = new Uint8Array(BATCH);
  const stem = "ktext_1360_0x" + result.kbase.toString(16);
  let ok = 0;

  for (let i = 0; i < PARTS; i++) {
    log("probe: part " + (i + 1) + "/" + PARTS + " memcpy");
    try {
      await kern.chain.call(
        memcpy,
        dst,
        result.kbase.add32(i * BATCH),
        new int64(BATCH, 0)
      );
    } catch (e) {
      log("probe: memcpy threw at part " + i + " (" + e + ") — stopping");
      return;
    }
    log("probe: part " + (i + 1) + " extract");
    for (let j = 0; j < BATCH; j += 4) {
      const v = p.read4(dst.add32(j));
      out[j] = v & 0xff;
      out[j + 1] = (v >>> 8) & 0xff;
      out[j + 2] = (v >>> 16) & 0xff;
      out[j + 3] = (v >>> 24) & 0xff;
    }
    log("probe: part " + (i + 1) + " post");
    if (await postPart(stem + "_part" + i + ".bin", out)) ok++;
  }

  log("probe: done, " + ok + "/" + PARTS + " parts on collector", "info");
}
