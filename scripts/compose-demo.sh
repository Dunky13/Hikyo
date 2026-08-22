#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
demo_dir="$repo_root/install/compose/demo"
docker_config_dir=${DOCKER_CONFIG:-${HOME:?}/.docker}
tmp_dir=${TMPDIR:-/tmp}
tmp_dir=${tmp_dir%/}
work_dir=$(mktemp -d "$tmp_dir/hikyo-compose-demo.XXXXXX")
project_dir="$work_dir/project"
runtime_dir="$work_dir/runtime"
state_dir="$work_dir/state"
home_dir="$work_dir/home"
binary="$work_dir/hikyo"
token_file="$work_dir/hikyo-token"
server_pid=''
pending_versions=''

cleanup() {
	if [[ -n "$server_pid" ]]; then
		kill "$server_pid" 2>/dev/null || true
		wait "$server_pid" 2>/dev/null || true
	fi
	docker compose --project-directory "$project_dir" down --remove-orphans >/dev/null 2>&1 || true
	if [[ -n "${runtime_tmpfs_mounted:-}" ]]; then
		sudo umount "$runtime_dir" 2>/dev/null || true
	fi
	chmod -R u+w "$work_dir" 2>/dev/null || true
	rm -rf -- "$work_dir"
}
trap cleanup EXIT INT TERM

fail() {
	printf 'compose demo: %s\n' "$*" >&2
	exit 1
}

need() {
	command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

totp_code() {
	python3 - "$1" "${2:-0}" <<'PY'
import base64
import hashlib
import hmac
import struct
import sys
import time
import urllib.parse

uri = open(sys.argv[1], encoding="utf-8").read().strip()
query = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)
digits = int(query.get("digits", ["6"])[0])
period = int(query.get("period", ["30"])[0])
secret = base64.b32decode(query["secret"][0])
counter = int(time.time()) // period + int(sys.argv[2])
digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = digest[-1] & 15
number = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % (10 ** digits)
print(str(number).zfill(digits))
PY
}

publish_pending() {
	[[ -n "$pending_versions" ]] || fail 'no staged versions to publish'
	"$binary" values publish --context demo --org "$org_id" --project "$project_id" --env "$env_id" --versions "$pending_versions" >/dev/null
	pending_versions=''
}

set_value() {
	local key_name=$1 value_file=$2 response version
	response=$("$binary" values set "$key_name" --context demo --org "$org_id" --project "$project_id" --env "$env_id" --stdin -o json <"$value_file")
	version=$(printf '%s' "$response" | jq -er '.version_id')
	pending_versions+="${pending_versions:+,}$version"
}

trim_space() {
	python3 - "$1" "$2" <<'PY'
import pathlib
import sys

# Match Go strings.TrimSpace exactly: these are the Unicode White_Space runes
# used by unicode.IsSpace. The demo compares STORED bytes (TrimSpace(input))
# with DELIVERED bytes; leading/trailing-whitespace rows prove that trim is the
# only transformation. allow_empty is enabled, so whitespace-only inputs would
# deliberately be stored and delivered as empty values.
spaces = {
    *range(0x0009, 0x000E),
    0x0020,
    0x0085,
    0x00A0,
    0x1680,
    *range(0x2000, 0x200B),
    0x2028,
    0x2029,
    0x202F,
    0x205F,
    0x3000,
}
value = pathlib.Path(sys.argv[1]).read_bytes().decode("utf-8")
start = 0
end = len(value)
while start < end and ord(value[start]) in spaces:
    start += 1
while end > start and ord(value[end - 1]) in spaces:
    end -= 1
pathlib.Path(sys.argv[2]).write_bytes(value[start:end].encode("utf-8"))
PY
}

need curl
need docker
need expect
need jq
need python3

mkdir -m 700 "$project_dir" "$runtime_dir" "$state_dir" "$home_dir"

# On Linux the runtime dir must BE tmpfs, not merely be tolerated as a doctor
# finding: `compose sync` runs doctor itself and refuses to render on any
# error-severity finding, so a non-tmpfs runtime (GitHub runners put /tmp on
# ext4) dead-ends the demo at sync. Mounting a real tmpfs satisfies the
# ops-spec § 6 property the check enforces instead of allowlisting its
# violation. macOS has no tmpfs; doctor's check does not fire there.
runtime_tmpfs_mounted=''
if [[ "$(uname -s)" == Linux ]] && ! findmnt -n -t tmpfs -- "$runtime_dir" >/dev/null 2>&1; then
	sudo mount -t tmpfs -o size=16m,mode=700,uid="$(id -u)",gid="$(id -g)" tmpfs "$runtime_dir" ||
		fail 'could not mount a tmpfs for the runtime dir'
	runtime_tmpfs_mounted=1
fi
python3 - "$demo_dir" "$project_dir" "$runtime_dir" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
runtime_dir = sys.argv[3]

compose = (source / "compose.yaml").read_text()
compose = compose.replace("/tmp/hikyo-demo-runtime", runtime_dir)
(destination / "compose.yaml").write_text(compose)
(destination / "hikyo-compose.yaml").write_text(
    (source / "hikyo-compose.yaml").read_text().replace(
        "/tmp/hikyo-demo-runtime", runtime_dir
    )
)
PY

(
	cd "$repo_root"
	go build -o "$binary" ./cmd/hikyo
)
export HOME="$home_dir"
export HIKYO_STATE_DIR="$state_dir"
export DOCKER_CONFIG="$docker_config_dir"

port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
origin="http://127.0.0.1:$port"
(
	cd "$work_dir"
	"$binary" server --dev --listen "127.0.0.1:$port" >server.log 2>&1 &
	printf '%s\n' "$!" >server.pid
)
server_pid=$(<"$work_dir/server.pid")

healthy=false
for _ in {1..200}; do
	if curl -fsS "$origin/healthz" >/dev/null 2>&1; then
		healthy=true
		break
	fi
	if ! kill -0 "$server_pid" 2>/dev/null; then
		break
	fi
	sleep 0.1
done
if [[ "$healthy" != true ]]; then
	sed -n '1,200p' "$work_dir/server.log" >&2
	fail "server did not become healthy at $origin"
fi

root_key=$(tr -d '\n' <"$work_dir/hikyo-dev.rootkey")
admin_log="$work_dir/admin.log"
(
	cd "$work_dir"
	HIKYO_DB=sqlite:hikyo-dev.db HIKYO_ROOT_KEY="$root_key" \
		"$binary" admin create --username compose-admin --display-name 'Compose Demo' \
		--output-file "$work_dir/authority" >"$admin_log" 2>&1
)
admin_principal=$(sed -n 's/.*principal \([^)]*\)).*/\1/p' "$admin_log")
[[ -n "$admin_principal" ]] || fail 'admin create did not report its principal id'

(
	cd "$work_dir"
	HIKYO_DB=sqlite:hikyo-dev.db HIKYO_ROOT_KEY="$root_key" \
		"$binary" admin grant --principal "$admin_principal" --capability instance-config >/dev/null
)

authority=$(tr -d '\n' <"$work_dir/authority")
password='compose-demo-password-long-enough'
establish_status=$(curl -sS -o "$work_dir/establish.json" -w '%{http_code}' \
	-H 'Content-Type: application/json' \
	--data "$(jq -cn --arg authority "$authority" --arg password "$password" '{authority:$authority,password:$password}')" \
	"$origin/api/v1/auth/credential/establish")
[[ "$establish_status" == 204 ]] || fail "credential establishment returned HTTP $establish_status"

cookie_jar="$work_dir/cookies"
login_status=$(curl -sS -o "$work_dir/login.json" -w '%{http_code}' -c "$cookie_jar" -H 'Content-Type: application/json' \
	--data "$(jq -cn --arg username compose-admin --arg password "$password" '{username:$username,password:$password,artifact:"browser"}')" \
	"$origin/api/v1/auth/local/login")
[[ "$login_status" == 200 ]] || fail "browser login returned HTTP $login_status: $(<"$work_dir/login.json")"
csrf=$(awk '$6 == "__Host-hikyo-csrf" { value=$7 } END { print value }' "$cookie_jar")
[[ -n "$csrf" ]] || fail 'browser login did not set the CSRF cookie'
totp_start_status=$(curl -sS -o "$work_dir/totp.json" -w '%{http_code}' -b "$cookie_jar" -c "$cookie_jar" -H 'Content-Type: application/json' \
	-H "X-Hikyo-CSRF: $csrf" --data "$(jq -cn --arg password "$password" '{password:$password}')" \
	"$origin/api/v1/auth/totp/enrol/start")
[[ "$totp_start_status" == 200 ]] || fail "TOTP enrol start returned HTTP $totp_start_status: $(<"$work_dir/totp.json")"
jq -er '.otpauth_uri' "$work_dir/totp.json" >"$work_dir/totp-uri"
totp_confirm_status=401
totp_attempts=''
for step_offset in 0 1 2; do
	code=$(totp_code "$work_dir/totp-uri" "$step_offset")
	csrf=$(awk '$6 == "__Host-hikyo-csrf" { value=$7 } END { print value }' "$cookie_jar")
	totp_confirm_status=$(curl -sS -o "$work_dir/totp-confirm.json" -w '%{http_code}' -b "$cookie_jar" -c "$cookie_jar" -H 'Content-Type: application/json' \
		-H "X-Hikyo-CSRF: $csrf" --data "$(jq -cn --arg code "$code" '{code:$code}')" \
		"$origin/api/v1/auth/totp/enrol/confirm")
	totp_attempts+="${totp_attempts:+, }offset $step_offset: HTTP $totp_confirm_status"
	[[ "$totp_confirm_status" == 200 || "$totp_confirm_status" == 204 ]] && break
done
[[ "$totp_confirm_status" == 200 || "$totp_confirm_status" == 204 ]] || fail "TOTP enrol confirm failed ($totp_attempts): $(<"$work_dir/totp-confirm.json")"

confirmed_step=$(( $(date +%s) / 30 + step_offset ))
while (( $(date +%s) / 30 <= confirmed_step )); do
	sleep 0.2
done

export DEMO_BINARY="$binary" DEMO_ORIGIN="$origin" DEMO_PASSWORD="$password" DEMO_TOTP_URI="$work_dir/totp-uri"
expect <<'EOF' >/dev/null
set timeout 15
spawn $env(DEMO_BINARY) login $env(DEMO_ORIGIN) --local --as compose-admin
expect -re {Record it.*:}
send "y\r"
expect -re {Password.*:}
send "$env(DEMO_PASSWORD)\r"
expect eof
catch wait result
exit [lindex $result 3]
EOF

"$binary" context create demo --instance "$origin"
export DEMO_TOTP_CODE
DEMO_TOTP_CODE=$(totp_code "$work_dir/totp-uri")
expect <<'EOF' >/dev/null
set timeout 15
spawn $env(DEMO_BINARY) account factor step-up --context demo
expect -re {(authenticator|TOTP|code).*:}
send "$env(DEMO_TOTP_CODE)\r"
expect eof
catch wait result
exit [lindex $result 3]
EOF
org_json=$("$binary" org create --context demo --name compose-demo -o json)
org_id=$(printf '%s' "$org_json" | jq -er '.id')

# Organisation creation atomically grants the creator the org-admin template
# and invalidates the session that performed the privilege increase. Prove the
# created grants, rather than seeding equivalent break-glass grants out of band:
# start a fresh session, step it up, then create the first project with the
# creator's ordinary authority.
last_totp_step=$(( $(date +%s) / 30 ))
while (( $(date +%s) / 30 <= last_totp_step )); do
	sleep 0.2
done
expect <<'EOF' >/dev/null
set timeout 15
spawn $env(DEMO_BINARY) login $env(DEMO_ORIGIN) --local --as compose-admin
expect -re {Password.*:}
send "$env(DEMO_PASSWORD)\r"
expect eof
catch wait result
exit [lindex $result 3]
EOF
DEMO_TOTP_CODE=$(totp_code "$work_dir/totp-uri")
export DEMO_TOTP_CODE
expect <<'EOF' >/dev/null
set timeout 15
spawn $env(DEMO_BINARY) account factor step-up --context demo
expect -re {(authenticator|TOTP|code).*:}
send "$env(DEMO_TOTP_CODE)\r"
expect eof
catch wait result
exit [lindex $result 3]
EOF
set +e
project_create_error=$("$binary" project create --context demo --org "$org_id" --name stack 2>&1)
project_create_code=$?
set -e
if (( project_create_code != 0 )); then
	fail "CLI blocker: project create after org-scoped grants and fresh MFA session exited $project_create_code: $project_create_error"
fi
project_json=$("$binary" project list --context demo --org "$org_id" -o json)
project_id=$(printf '%s' "$project_json" | jq -er 'first(.. | objects | select(.name? == "stack") | .id)')
set +e
environment_create_error=$("$binary" env create --context demo --org "$org_id" --project "$project_id" --name demo 2>&1)
environment_create_code=$?
set -e
if (( environment_create_code != 0 )); then
	fail "CLI blocker: env create after org-scoped grants and fresh MFA session exited $environment_create_code: $environment_create_error"
fi
env_json=$("$binary" env list --context demo --org "$org_id" --project "$project_id" -o json)
env_id=$(printf '%s' "$env_json" | jq -er 'first(.. | objects | select(.name? == "demo") | .id)')

representable="$work_dir/representable.jsonl"
for corpus in "$repo_root"/internal/compose/testdata/roundtrip/*.json; do
	jq -c '.rows[] as $row | select(([.expectRefusals[].key] | index($row.name)) == null) | $row' "$corpus" >>"$representable"
done
jq -cn '{name:"GREETING",value:"hello from hikyo"}' >>"$representable"

while IFS= read -r row; do
	name=$(printf '%s' "$row" | jq -r '.name')
	"$binary" key create --context demo --org "$org_id" --project "$project_id" \
		--name "$name" --classification config --declaration '{"rule":{"type":"string","allow_empty":true}}' >/dev/null
done <"$representable"
"$binary" key create --context demo --org "$org_id" --project "$project_id" \
	--name EMBEDDED_NL --classification config --declaration '{"rule":{"type":"string","allow_empty":true}}' >/dev/null

keys_json=$("$binary" key list --context demo --org "$org_id" --project "$project_id" -o json)
key_ids=''
while IFS= read -r row; do
	name=$(printf '%s' "$row" | jq -r '.name')
	value_file="$work_dir/value-$name"
	printf '%s' "$row" | jq -j '.value' >"$value_file"
	trim_space "$value_file" "$work_dir/expected-$name"
	key_id=$(printf '%s' "$keys_json" | jq -er --arg name "$name" 'first(.. | objects | select(.name? == $name) | .id)')
	key_ids+="${key_ids:+, }$key_id"
	set_value "$name" "$value_file"
done <"$representable"
newline_key=$(printf '%s' "$keys_json" | jq -er 'first(.. | objects | select(.name? == "EMBEDDED_NL") | .id)')
printf 'line1\nline2' >"$work_dir/value-EMBEDDED_NL"
set_value EMBEDDED_NL "$work_dir/value-EMBEDDED_NL"
publish_pending

"$binary" sa create --context demo --org "$org_id" --project "$project_id" --name compose-demo --kind workload >/dev/null
sa_json=$("$binary" sa list --context demo --org "$org_id" --project "$project_id" -o json)
sa_id=$(printf '%s' "$sa_json" | jq -er 'first(.. | objects | select(.name? == "compose-demo") | .id)')
sa_principal=$(printf '%s' "$sa_json" | jq -er 'first(.. | objects | select(.name? == "compose-demo") | (.principal_id // .principal.id // .principal))')
"$binary" access grant add --context demo --org "$org_id" --project "$project_id" --env "$env_id" \
	--principal "$sa_principal" --capability read >/dev/null
"$binary" sa credential mint --context demo --org "$org_id" --project "$project_id" \
	--sa "$sa_id" --output-file "$token_file" >/dev/null
chmod 600 "$token_file"

python3 - "$project_dir/hikyo-compose.yaml" "$origin" "$org_id" "$project_id" "$env_id" "$key_ids" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
text = text.replace("http://127.0.0.1:1", sys.argv[2])
text = text.replace("__HIKYO_ORG__", sys.argv[3])
text = text.replace("__HIKYO_PROJECT__", sys.argv[4])
text = text.replace("__HIKYO_ENVIRONMENT__", sys.argv[5])
text = text.replace("__HIKYO_KEYS__", sys.argv[6])
path.write_text(text)
PY

HIKYO_TOKEN=$(tr -d '\n' <"$token_file") "$binary" compose render --project-directory "$project_dir"
initial_env=$(cksum "$project_dir/.env")
initial_runtime=$(find "$runtime_dir" -type f -print | sort | while IFS= read -r file; do cksum "$file"; done)

python3 - "$project_dir/hikyo-compose.yaml" "$newline_key" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text().replace("keys: [", "keys: [" + sys.argv[2] + ", ", 1)
path.write_text(text)
PY
set +e
refusal=$(HIKYO_TOKEN=$(tr -d '\n' <"$token_file") "$binary" compose render --project-directory "$project_dir" 2>&1)
refusal_code=$?
set -e
[[ $refusal_code -eq 4 ]] || fail "embedded-newline render exited $refusal_code, want 4: $refusal"
grep -F 'EMBEDDED_NL' <<<"$refusal" >/dev/null || fail 'embedded-newline refusal did not name EMBEDDED_NL'
[[ "$(cksum "$project_dir/.env")" == "$initial_env" ]] || fail 'refused render changed .env'
after_refusal_runtime=$(find "$runtime_dir" -type f -print | sort | while IFS= read -r file; do cksum "$file"; done)
[[ "$after_refusal_runtime" == "$initial_runtime" ]] || fail 'refused render changed a generation'
python3 - "$project_dir/hikyo-compose.yaml" "$newline_key" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text().replace("keys: [" + sys.argv[2] + ", ", "keys: [", 1)
path.write_text(text)
PY

docker compose --project-directory "$project_dir" config >/dev/null
docker compose --project-directory "$project_dir" up --abort-on-container-exit >/dev/null
docker compose --project-directory "$project_dir" logs --no-color app >"$work_dir/container.log"
while IFS= read -r row; do
	name=$(printf '%s' "$row" | jq -r '.name')
	want=$(base64 <"$work_dir/expected-$name" | tr -d '\n')
	if ! grep -F "$name=$want" "$work_dir/container.log" >/dev/null; then
		got=$(sed -n "s/^.*$name=//p" "$work_dir/container.log")
		fail "container did not round-trip $name (want base64 $want, got ${got:-missing})"
	fi
done <"$representable"

docker_wrapper_dir="$work_dir/docker-wrapper"
mkdir -m 700 "$docker_wrapper_dir"
real_docker=$(command -v docker)
python3 - "$docker_wrapper_dir/docker" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text("""#!/usr/bin/env bash
set -euo pipefail
has_config=false
has_no_env_resolution=false
for arg in "$@"; do
    [[ "$arg" == config ]] && has_config=true
    [[ "$arg" == --no-env-resolution ]] && has_no_env_resolution=true
done
if [[ "$has_config" == true && "$has_no_env_resolution" == false ]]; then
    exec "${DEMO_REAL_DOCKER:?}" "$@" --no-env-resolution
fi
exec "${DEMO_REAL_DOCKER:?}" "$@"
""")
path.chmod(0o700)
PY
set +e
DEMO_REAL_DOCKER="$real_docker" PATH="$docker_wrapper_dir:$PATH" \
	HIKYO_TOKEN=$(tr -d '\n' <"$token_file") \
	"$binary" compose doctor --project-directory "$project_dir" -o json >"$work_dir/doctor.json"
doctor_code=$?
set -e
[[ $doctor_code -eq 0 || $doctor_code -eq 4 ]] || fail "doctor exited $doctor_code"
jq -e '
	(.status == "ok" or .status == "error" or .status == "warning") and
	(.findings | type == "array") and
	all(.findings[];
		(has("check") and (.check | type == "string")) and
		(has("status") and (.status | type == "string")) and
		(
			(.check == "runtime_not_tmpfs" and .status == "error") or
			(.check == "systemd_plain_token_file" and .status == "warn")
		)
	)
' "$work_dir/doctor.json" >/dev/null || {
	jq . "$work_dir/doctor.json" >&2
	fail 'doctor returned a finding outside the environmental allowlist'
}

printf '%s' 'hello after sync' >"$work_dir/value-GREETING-updated"
set_value GREETING "$work_dir/value-GREETING-updated"
publish_pending
before_sync_env=$(cksum "$project_dir/.env")
DEMO_REAL_DOCKER="$real_docker" PATH="$docker_wrapper_dir:$PATH" \
	HIKYO_TOKEN=$(tr -d '\n' <"$token_file") \
	"$binary" compose sync --project-directory "$project_dir"
after_sync_env=$(cksum "$project_dir/.env")
[[ "$after_sync_env" != "$before_sync_env" ]] || fail 'sync did not move the managed stamp'
for _ in {1..100}; do
	[[ -z "$(docker compose --project-directory "$project_dir" ps --status running -q)" ]] && break
	sleep 0.1
done
docker compose --project-directory "$project_dir" logs --no-color app >"$work_dir/sync.log"
updated=$(printf '%s' 'hello after sync' | base64 | tr -d '\n')
grep -F "GREETING=$updated" "$work_dir/sync.log" >/dev/null || fail 'sync did not restart app with the updated GREETING'

printf 'compose demo passed: %s stored values including GREETING delivered byte-exactly; surrounding whitespace proved trim-only transformation\n' "$(wc -l <"$representable" | tr -d ' ')"
printf 'compose demo passed: embedded newline refused by name with exit 4 and no generation/stamp change\n'
printf 'compose demo passed: doctor returned only allowed findings; sync moved the stamp and restarted app\n'
