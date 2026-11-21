#!/bin/sh
# Builds the Windows exes into dist/ with SHA-256 checksums.
# Usage: scripts/build-windows.sh v0.1.0
set -eu

version="${1:?usage: scripts/build-windows.sh <version, e.g. v0.1.0>}"
cd "$(dirname "$0")/.."
mkdir -p dist

for arch in amd64 arm64; do
	out=dist/jacktrace.exe
	[ "$arch" = arm64 ] && out=dist/jacktrace-arm64.exe
	GOOS=windows GOARCH="$arch" CGO_ENABLED=0 \
		go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$out" ./cmd/jacktrace
done

cd dist
if command -v sha256sum >/dev/null 2>&1; then
	sha256sum jacktrace.exe jacktrace-arm64.exe >SHA256SUMS.txt
else
	shasum -a 256 jacktrace.exe jacktrace-arm64.exe >SHA256SUMS.txt
fi
cat SHA256SUMS.txt
