# php-scan

Scans a server and every container image stored on it for PHP, to help
inventory your systems and work out whether they're vulnerable to PHP2Shell
(CVE-2026-109618, CVE-2026-109619).

It checks PHP binaries, Apache modules and dpkg, apk and rpm packages, on the
host and in Docker, containerd, k3s, RKE2 and Podman storage.

## Run

The scan needs the host's filesystem, not just its own container's: each way
below mounts the host's `/` (read-only) or runs on the host directly. Use
whichever fits the server; Docker works on macOS too (OrbStack, Docker
Desktop).

### Docker

```sh
docker run --rm -t --pull always \
  -v /:/host:ro --security-opt label=disable \
  ghcr.io/rpendleton/php-scan
```

### containerd (`ctr`)

```sh
sudo ctr image pull ghcr.io/rpendleton/php-scan:latest

sudo ctr run --rm -t \
  --mount type=bind,src=/,dst=/host,options=rbind:ro \
  ghcr.io/rpendleton/php-scan:latest php-scan
```

### Talos

```sh
talosctl image remove --namespace system ghcr.io/rpendleton/php-scan:latest

talosctl debug ghcr.io/rpendleton/php-scan --namespace system
```

The first `remove` makes the node pull the current image; a node that already
has the tag would run the old one. It prints `not found` on a node that hasn't
run the scan before.

### Kubernetes

Every node in turn:

```sh
for n in $(kubectl get nodes -o name); do
  echo "=== $n"
  out=$(kubectl debug "$n" -n kube-system --profile=sysadmin \
    --image=ghcr.io/rpendleton/php-scan --image-pull-policy=Always 2>&1)
  pod=$(echo "$out" | sed -n 's/^Creating debugging pod \([^ ]*\) .*/\1/p')
  if [ -z "$pod" ]; then echo "ERROR: kubectl debug failed: $out"; continue; fi
  ok=
  for i in $(seq 60); do
    kubectl -n kube-system logs -f "pod/$pod" 2>/dev/null && { ok=1; break; }
    sleep 2
  done
  if [ -z "$ok" ]; then
    echo "ERROR: no logs from $pod. To see why:"
    echo "  kubectl -n kube-system describe pod/$pod"
  fi
  kubectl -n kube-system delete "pod/$pod" --wait=false
done
```

One node, interactively. Press Enter at the prompt:

```sh
kubectl debug node/<name> -it \
  -n kube-system --profile=sysadmin \
  --image=ghcr.io/rpendleton/php-scan --image-pull-policy=Always \
  --arguments-only -- --wait /host

# clean up, with the pod name kubectl printed
kubectl -n kube-system delete pod <pod>
```

On a single-node cluster, `"$(kubectl get nodes -o name)"` works in place of
`node/<name>`. The namespace has to allow privileged pods (`kube-system`
usually does).

### Binary

Download `php-scan-<os>-<arch>` for Linux or macOS from the artifacts of the
latest run of [ci.yml](https://github.com/rpendleton/php-scan/actions/workflows/ci.yml)
on `main`, unzip it, then:

```sh
chmod +x php-scan-*
xattr -d com.apple.quarantine php-scan-*    # macOS only

sudo ./php-scan-*
```

Run on the host, it also shows each PHP binary's `-v` and reads rpm databases
with `rpm -qa`. On macOS it finds Homebrew PHP and PHP under `/Applications`
(MAMP), but not images in a Docker VM; use [Docker](#docker) for those.

### Options

```sh
php-scan [--wait] [host-root] [extra storage dirs...]
```

- `host-root`: where the host's `/` is mounted (default `/`; `/host` in the
  image).
- `extra storage dirs`: container storage in a non-default place, such as a
  Docker `data-root`: `php-scan /host /srv/docker`.
- `--wait`: wait for Enter before scanning.

With `ctr`, arguments replace the whole command:

```sh
sudo ctr run --rm -t \
  --mount type=bind,src=/,dst=/host,options=rbind:ro \
  ghcr.io/rpendleton/php-scan:latest php-scan php-scan /host /srv/docker
```

## Reading the result

With Docker's overlay2 storage, the report shows what each image runs:

```
[containers] /var/lib/docker: 46 layers in overlay2; 6 docker images
  image php:8.3.10-fpm-alpine
      binary php  PHP 8.3.10  /usr/local/bin/php
      binary php-fpm  PHP 8.3.10  /usr/local/sbin/php-fpm
  image my-app:latest
      binary php  PHP 8.3.36  /usr/local/bin/php
      replaced or removed later: binary php  PHP 8.3.10  /usr/local/bin/php
  container web (my-app:latest) writable layer
      binary php  PHP 8.3.36  /tmp/php
  not in any image or container (build cache, or layers of deleted images):
      binary php  PHP 8.3.36  (/var/lib/docker/overlay2/ah6g…/diff/php)

RESULT: PHP found: 2 image(s) with PHP; 1 container(s) added PHP in their own layer; 1 in layers no image or container uses.
```

- **Coverage:** before the findings, it lists the storage it found and its
  layer and image counts, and at the end the totals scanned. Small numbers mean
  it didn't see the storage.
- **Versions** are read from the files (`X-Powered-By: PHP/<version>`), so
  nothing from an image is run, and files that are only named like PHP are
  skipped; packages show their package version. The scanner doesn't
  judge them: upstream fixed PHP2Shell in 8.5.12, 8.4.27, 8.3.36 and 8.2.35,
  but distros and custom builds can backport the fix without changing the
  version.
- **Per image:** each image shows the copy at the top of its layers; copies a
  later layer overrides are listed as replaced. Storage without Docker's image
  metadata (containerd, Talos) lists findings by layer path.
- **Exit status:** 0 no PHP, 1 PHP found, 2 couldn't scan.

PHP built into another program under a different name isn't found.
