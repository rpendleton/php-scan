# Agent notes

php-scan inventories PHP on a host and in its container image layers, to help work out exposure to PHP2Shell (CVE-2026-109618/109619). `README.md` covers what it reports and how to run it; this file covers changing it.

## Layout

- `main.go`: arguments, the host and container-storage scans, package database parsing, version strings, the progress line.
- `docker.go`: maps Docker overlay2 layer directories to the images and containers that use them, from `image/overlay2` metadata.
- `version_test.go`: reading the embedded version string.
- `report.go`: the per-image report for Docker storage (which copy each image runs, what's replaced, containers, unused layers) and the `RESULT` tally.
- `Dockerfile` builds a static binary into `scratch`; `docker-bake.hcl` builds it for amd64 and arm64 as `ghcr.io/rpendleton/php-scan`, a public package.
- `.github/workflows/ci.yml`: `build` runs the checks below (vet for each platform, tests on linux/amd64), builds linux/darwin amd64/arm64 and uploads them as artifacts (the README's Binary method links there); `test-linux` scans the runner with the linux build, and `test-macos` scans a macOS runner with Homebrew PHP using the darwin build; after both, pushes to `main` publish the image and `v*` tags attach the binaries and `SHA256SUMS` to a release. Builds set `main.version` to the tag, or `dev-<sha>`.

## Rules

- **Standard library only.** No `go.sum`; keep it that way so the image stays one static binary.
- **Never run a binary from an image or another root.** Versions come from the file's bytes (`X-Powered-By: PHP/<version>`). `-v` runs only when the root is `/`, during the host scan, for files that carry that string and aren't under container storage; `rpm -qa` only on the host. Files named like PHP without the string (scripts, man pages, package hooks) are counted as skipped, never run or reported.
- **Read only.** It walks with `filepath.WalkDir`, which doesn't follow symlinks; it must not write under the root it scans.
- **No silent results.** A clean result has to show what was covered: storage roots found or missing, layer and image counts, totals. Anything it can't scan says so, and a root that isn't a filesystem exits 2. This came from a version whose errors went to `/dev/null`, so "no output" passed for "no PHP".
- **Versions, not verdicts.** It reports the version each binary or package carries and leaves the call to the reader: distros and custom builds backport fixes without changing the version. The upstream fixed releases are listed in `README.md` only.

## Checking a change

```sh
gofmt -l . && go vet ./... && go test ./...
```

Then run it against fake roots: `php-scan <dir>` scans `<dir>` as the host's `/`, so a tree with `usr/`, `etc/`, `etc/os-release` and, say, `var/lib/docker/overlay2/<id>/diff/usr/local/bin/php` (an executable file) exercises a path without real servers. For real layouts, a local `dockerd` gives the containerd image store by default, or classic overlay2 (with the layer-to-image mapping) with `{"features":{"containerd-snapshotter":false}}` in `/etc/docker/daemon.json`. Pull an official `php` image, start a container from it, and scan `/` through the image:

```sh
docker buildx bake --set default.platforms=linux/amd64 \
  --set default.output=type=docker --set default.tags=php-scan:test

docker run --rm -v /:/host:ro php-scan:test
```

Keep `README.md`'s run commands in step with flag or output changes. They use `<node>` and `<name>` placeholders, never real addresses.
