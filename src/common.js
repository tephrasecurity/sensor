// Shared by main (start the sensor) and post (stop it, upload what it recorded).
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const core = require("@actions/core");

const SENSOR = path.join(__dirname, "..", "sensor.py");
const DIR = path.join(process.env.RUNNER_TEMP || "/tmp", "tephra-sensor");

function supported() {
  if (process.platform !== "linux") {
    core.warning(`tephra-sensor: ${process.platform} runners aren't supported yet; the job runs unmonitored.`);
    return false;
  }
  const sudo = spawnSync("sudo", ["-n", "true"]);
  if (sudo.status !== 0) {
    core.warning("tephra-sensor: needs passwordless sudo; the job runs unmonitored.");
    return false;
  }
  return true;
}

function env() {
  const allowed = core.getInput("allowed-endpoints");
  const e = {
    ...process.env,
    TEPHRA_DIR: DIR,
    TEPHRA_MODE: (core.getInput("egress-policy") || "audit").toLowerCase(),
    TEPHRA_ALLOWED: allowed,
    TEPHRA_CONSOLE_URL: core.getInput("console-url"),
    TEPHRA_INGEST_TOKEN: core.getInput("ingest-token"),
    TEPHRA_INTEL: core.getInput("threat-intel") || "on",
  };
  if (e.TEPHRA_INGEST_TOKEN) core.setSecret(e.TEPHRA_INGEST_TOKEN);
  return e;
}

// Settings reach the root sensor in a file, not through sudo: newer runner images ship a sudo that ignores -E
// (and --preserve-env varies). Only what the sensor reads is written, mode 0600; the sensor deletes it on read.
// ACTIONS_ID_TOKEN_REQUEST_*: present only when the job has id-token: write; with them and no ingest-token, the
// sensor signs in to the console with the job's own OIDC token, so no stored secret is needed.
const PASS = /^(GITHUB_|RUNNER_|TEPHRA_)|^(PATH|HOME|ImageOS|ImageVersion|ACTIONS_ID_TOKEN_REQUEST_URL|ACTIONS_ID_TOKEN_REQUEST_TOKEN)$/;

function sensor(cmd) {
  const vars = Object.fromEntries(Object.entries(env()).filter(([k, v]) => PASS.test(k) && v !== undefined));
  const file = path.join(process.env.RUNNER_TEMP || "/tmp", `tephra-sensor-${cmd}-${process.pid}.json`);
  fs.writeFileSync(file, JSON.stringify(vars), { mode: 0o600 });
  try {
    return spawnSync("sudo", ["-n", "python3", SENSOR, cmd, "--env-file", file], { stdio: "inherit", env: env() });
  } finally {
    try { fs.unlinkSync(file); } catch (_) { /* the sensor already removed it */ }
  }
}

module.exports = { core, fs, path, DIR, supported, sensor };
