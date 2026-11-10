const { core, fs, path, DIR, supported, sensor } = require("./common");

try {
  if (supported()) {
    const r = sensor("start");
    if (r.status !== 0) {
      const msg = "tephra-sensor didn't start; the job runs unmonitored.";
      if ((core.getInput("fail-on-error") || "false") === "true") core.setFailed(msg); else core.warning(msg);
    } else {
      core.saveState("started", "1");
    }
  }
} catch (e) {
  core.warning(`tephra-sensor: ${e.message}`);
}
