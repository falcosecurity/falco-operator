#!/usr/bin/env bash
# Prints, as NAME=VALUE lines, the component versions the operator deploys by default, read from
# internal/pkg/image/defaults.go. The chainsaw e2e tests compare a component's reported version
# with these, so bumping a default in defaults.go needs no change to the tests.
set -euo pipefail

defaults="$(dirname "${BASH_SOURCE[0]}")/../internal/pkg/image/defaults.go"

tag() {
	local value
	value="$(sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"\([^\"]*\)\".*/\1/p" "${defaults}")"
	if [[ -z "${value}" ]]; then
		echo "$1 not found in ${defaults}" >&2
		return 1
	fi
	echo "${value}"
}

falcosidekick="$(tag FalcosidekickTag)"
metacollector="$(tag MetacollectorTag)"

echo "CHAINSAW_DEFAULT_FALCOSIDEKICK_VERSION=${falcosidekick}"
echo "CHAINSAW_DEFAULT_METACOLLECTOR_VERSION=${metacollector}"
