#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
	printf 'usage: %s EVIDENCE_JSON FALLBACK_EMAIL\n' "$0" >&2
	exit 2
fi

evidence_file=$1
fallback_email=$2
NODE_BIN=${NODE_BIN:-node}

[ -f "$evidence_file" ] || {
	printf 'fallback channel gate: missing evidence %s\n' "$evidence_file" >&2
	exit 1
}

"$NODE_BIN" -e '
const { readFileSync } = require("node:fs");

const [evidenceFile, expectedAddress] = process.argv.slice(1);
const maxAgeMilliseconds = 93 * 24 * 60 * 60 * 1000;
const acknowledgementMilliseconds = 7 * 24 * 60 * 60 * 1000;
const futureToleranceMilliseconds = 5 * 60 * 1000;

function fail(message) {
  console.error("fallback channel gate: " + message);
  process.exit(1);
}

let evidence;
try {
  evidence = JSON.parse(readFileSync(evidenceFile, "utf8"));
} catch {
  fail("evidence is not valid JSON");
}

if (evidence.schema !== "wenv.dev/fallback-channel-test/v1") fail("unknown evidence schema");
if (evidence.address !== expectedAddress) fail("evidence address does not match fallback address");
if (evidence.status !== "passed") fail("latest notification test has not passed");
if (!/^[0-9a-f]{64}$/.test(evidence.message_id_sha256 || "")) {
  fail("message_id_sha256 is missing or invalid");
}

const sentAt = Date.parse(evidence.sent_at);
const receivedAt = Date.parse(evidence.received_at);
const now = Date.parse(process.env.WENV_FALLBACK_TEST_NOW || new Date().toISOString());
if (![sentAt, receivedAt, now].every(Number.isFinite)) fail("test timestamps are invalid");
if (receivedAt < sentAt) fail("receipt predates send time");
if (receivedAt - sentAt > acknowledgementMilliseconds) {
  fail("notification did not surface within the acknowledgement window");
}
if (receivedAt > now + futureToleranceMilliseconds) fail("receipt timestamp is in the future");
if (now - receivedAt > maxAgeMilliseconds) fail("notification test is older than one quarter");
' "$evidence_file" "$fallback_email"

printf 'fallback channel gate: recent end-to-end notification receipt passed\n'
