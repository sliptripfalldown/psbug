// Read-only kernel probe: dumps kernel memory around kbase to the host
// that served this page (POST /dump/<name>). Defensive by construction:
// pipe-aim reads return -1 on bad addresses (skipped), no kernel writes.

const CHUNK = 0x1000;
const DUMP_SIZE = 4 * 1024 * 1024; // first 4MB of kernel text; raise after review

function nameFor(kbase) {
  return "ktext_1360_0x" + kbase.toString(16) + ".bin";
}

async function postChunk(name, bytes) {
  await fetch("/dump/" + name, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: bytes,
  });
}

export async function dumpKernel(result, log) {
  const kern = result && result.kern;
  if (!kern || !result.kbase) {
    log("probe: no kernel context, skipping");
    return;
  }

  const name = nameFor(result.kbase);
  const buf = kern.p.malloc(CHUNK, 1);
  const out = new Uint8Array(CHUNK);
  let sent = 0;
  let gaps = 0;

  // Validation read before anything else: first page must be readable.
  const ok = await kern.kreadFast(result.kbase, 8, kern.scratch.qword);
  if (ok !== 8) {
    log("probe: kbase unreadable, aborting dump");
    return;
  }

  for (let offset = 0; offset < DUMP_SIZE; offset += CHUNK) {
    const n = await kern.kreadFast(result.kbase.add32(offset), CHUNK, buf);
    if (n !== CHUNK) {
      gaps++;
      continue;
    }
    for (let i = 0; i < CHUNK; i++) out[i] = kern.readU8(buf, i);
    try {
      await postChunk(name, out);
      sent += CHUNK;
    } catch (e) {
      log("probe: upload stopped at +0x" + offset.toString(16) + " (" + e + ")");
      break;
    }
  }

  log("probe: dumped 0x" + sent.toString(16) + " bytes, " + gaps + " gap pages -> dumps/" + name, "info");
}
