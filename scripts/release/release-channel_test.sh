#!/bin/sh
set -eu

script=$(dirname "$0")/release-channel.sh
[ "$("$script" v0.9.0)" = prerelease ]
[ "$("$script" v1.0.0-rc.1)" = prerelease ]
[ "$("$script" v1.0.0)" = stable ]
[ "$("$script" v2.4.1+build.7)" = stable ]
if "$script" 1.0.0 >/dev/null 2>&1; then
	printf 'release channel fixture failed: unprefixed version accepted\n' >&2
	exit 1
fi
printf 'release channel fixture: 0.x and SemVer prereleases separated from stable releases\n'
