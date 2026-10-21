// php-scan looks for PHP (PHP2Shell: CVE-2026-109618, CVE-2026-109619) on a
// host and in every container image layer stored by Docker, containerd, k3s,
// RKE2 or Podman. See README.md.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const usage = `Usage: php-scan [--wait] [host-root] [extra storage dirs...]
  host-root: where the host's / is mounted; default / (run on the host as root)
  --wait:    wait for Enter before scanning, for when the terminal attaches
             after the container starts (kubectl debug -it)
Exit: 0 nothing found, 1 PHP found, 2 couldn't scan.
`

// Storage roots, relative to the host root. Globs are allowed.
var storageRoots = []string{
	"/var/lib/docker",
	"/var/lib/containerd",
	"/var/lib/rancher/k3s/agent/containerd",
	"/var/lib/rancher/rke2/agent/containerd",
	"/var/lib/containers/storage",
	"/root/.local/share/containers/storage",
	"/home/*/.local/share/containers/storage",
	"/home/*/.local/share/docker",
}

// version is set at release builds with -ldflags "-X main.version=<tag>".
var version = "dev"

var (
	binName = regexp.MustCompile(`^(php|php[0-9].*|php-fpm.*|php-cgi.*|lsphp.*|frankenphp)$`)
	modName = regexp.MustCompile(`^(libphp.*|mod_php.*)\.so$`)
)

type finding struct {
	kind, what, path string
	layer, rel       string // for a layer: its directory and the path inside it
}

type scanner struct {
	root   string // host root, "/" or e.g. "/host"
	onHost bool   // root is "/": host binaries can be run for -v
	inHost bool   // scanning the host's own directories, not container storage

	findings []finding

	// Layer directories (each entry inside is a layer) and, for Docker, the
	// images and containers using each layer.
	layerDirs []string

	// While grouping, findings are kept for the per-image report instead of
	// printed as they're found.
	grouping bool
	tally    tally

	// Progress, read by the ticker.
	phase      atomic.Value // string
	dirs       atomic.Int64
	files      atomic.Int64
	dbs        atomic.Int64
	layersDone atomic.Int64
	layersAll  atomic.Int64
	found      atomic.Int64
	skipped    atomic.Int64 // named like PHP but without a PHP version string

	out      sync.Mutex
	tty      bool
	lastLine bool // a progress line is on screen
}

func main() {
	var args []string
	wait := false
	for _, a := range os.Args[1:] {
		switch {
		case a == "-h" || a == "--help":
			fmt.Print(usage)
			return
		case a == "--wait":
			wait = true
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(os.Stderr, "ERROR: unknown flag %s\n%s", a, usage)
			os.Exit(2)
		default:
			args = append(args, a)
		}
	}
	if wait {
		waitForEnter()
	}
	root := "/"
	if len(args) > 0 {
		root = filepath.Clean(args[0])
		args = args[1:]
	}
	s := &scanner{root: root, onHost: root == "/"}
	if fi, err := os.Stderr.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		s.tty = true
	}
	s.phase.Store("starting")
	stop := s.startProgress()
	code := s.run(args)
	stop()
	os.Exit(code)
}

// waitForEnter repeats its prompt, since a terminal that attaches late (as
// kubectl debug -it does) misses whatever came before. With stdin closed it
// starts at once rather than hang.
func waitForEnter() {
	const prompt = "php-scan: press Enter to start the scan"
	fmt.Fprintln(os.Stderr, prompt)
	done := make(chan error, 1)
	go func() {
		_, err := bufio.NewReader(os.Stdin).ReadString('\n')
		done <- err
	}()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case err := <-done:
			if err != nil {
				fmt.Fprintln(os.Stderr, "php-scan: no input on stdin, starting")
			}
			return
		case <-t.C:
			fmt.Fprintln(os.Stderr, prompt)
		}
	}
}

// host maps a host path to where it is under the root.
func (s *scanner) host(p string) string { return filepath.Join(s.root, p) }

// rel is the reverse, for printing.
func (s *scanner) rel(p string) string {
	if s.onHost {
		return p
	}
	if r, err := filepath.Rel(s.root, p); err == nil && !strings.HasPrefix(r, "..") {
		return "/" + r
	}
	return p
}

func (s *scanner) logf(format string, a ...any) {
	s.out.Lock()
	defer s.out.Unlock()
	s.clearProgress()
	fmt.Printf(format+"\n", a...)
}

func (s *scanner) hit(kind, what, path string) {
	f := finding{kind: kind, what: what, path: path}
	f.layer, f.rel = s.layerOf(path)
	s.findings = append(s.findings, f)
	s.found.Add(1)
	if !s.grouping {
		s.logf("  FOUND %-6s %s  (%s)", kind, what, s.rel(path))
	}
}

// --- progress

func (s *scanner) progressLine() string {
	l := fmt.Sprintf("[%s] %d dirs, %d files, %d package dbs", s.phase.Load(), s.dirs.Load(), s.files.Load(), s.dbs.Load())
	if all := s.layersAll.Load(); all > 0 {
		l += fmt.Sprintf(", layer %d/%d", s.layersDone.Load(), all)
	}
	return l + fmt.Sprintf(", %d found", s.found.Load())
}

func (s *scanner) clearProgress() {
	if s.tty && s.lastLine {
		fmt.Fprint(os.Stderr, "\r\033[K")
		s.lastLine = false
	}
}

// startProgress redraws one line on a terminal, or prints a line every 10s
// otherwise (logs, talosctl), on stderr so stdout stays the report.
func (s *scanner) startProgress() func() {
	every := 10 * time.Second
	if s.tty {
		every = 200 * time.Millisecond
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				s.out.Lock()
				if s.tty {
					fmt.Fprint(os.Stderr, "\r\033[K"+s.progressLine())
					s.lastLine = true
				} else {
					fmt.Fprintln(os.Stderr, "progress: "+s.progressLine())
				}
				s.out.Unlock()
			}
		}
	}()
	return func() {
		close(done)
		wg.Wait()
		s.out.Lock()
		s.clearProgress()
		s.out.Unlock()
	}
}

// --- run

func (s *scanner) run(extra []string) int {
	s.logf("php-scan %s: host root %s, running as uid %d", version, s.root, os.Getuid())
	if os.Getuid() != 0 {
		s.logf("WARNING: not root; unreadable files are skipped, so a clean result proves less")
	}
	for _, d := range []string{"/usr", "/etc"} {
		if fi, err := os.Stat(s.host(d)); err != nil || !fi.IsDir() {
			fmt.Fprintf(os.Stderr, "ERROR: %s doesn't look like a root filesystem (no usr/ and etc/); mount the host's / and pass its path\n", s.root)
			return 2
		}
	}
	s.logf("host OS: %s", osName(s.host("/etc/os-release")))

	s.scanHost()
	s.tally.host = len(s.findings)
	s.scanContainers(extra)

	s.logf("")
	s.logf("scanned %d dirs, %d files, %d package dbs", s.dirs.Load(), s.files.Load(), s.dbs.Load())
	if n := s.skipped.Load(); n > 0 {
		s.logf("skipped %d files named like PHP without a PHP version string (scripts, man pages, package hooks)", n)
	}
	if len(s.findings) == 0 {
		s.logf("RESULT: no PHP found")
		return 0
	}
	s.logf("RESULT: PHP found: %s.", s.tally)
	return 1
}

func osName(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unknown (no etc/os-release)"
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return "unknown"
}

// --- host

func (s *scanner) scanHost() {
	s.inHost = true
	defer func() { s.inHost = false }()
	s.phase.Store("host")
	s.logf("")
	s.logf("[host] package databases:")
	for _, db := range []string{"/var/lib/dpkg/status", "/lib/apk/db/installed", "/var/lib/rpm", "/usr/lib/sysimage/rpm"} {
		state := "missing"
		if _, err := os.Stat(s.host(db)); err == nil {
			state = "found  "
		}
		s.logf("  %s %s", state, db)
	}
	before := len(s.findings)

	s.checkFile(s.host("/var/lib/dpkg/status"))
	s.checkFile(s.host("/lib/apk/db/installed"))
	if rpmPath, err := exec.LookPath("rpm"); err == nil && s.onHost && (exists("/var/lib/rpm") || exists("/usr/lib/sysimage/rpm")) {
		s.logf("[host] reading the rpm database with rpm -qa")
		s.rpmQuery(rpmPath)
	} else {
		for _, d := range []string{"/var/lib/rpm", "/usr/lib/sysimage/rpm"} {
			s.walk(s.host(d), nil)
		}
	}

	var dirs []string
	hostDirs := []string{"/usr", "/opt", "/etc", "/srv", "/var/www"}
	if runtime.GOOS == "darwin" && s.onHost {
		hostDirs = append(hostDirs, "/Applications") // MAMP and other bundled PHP
	}
	for _, d := range hostDirs {
		if exists(s.host(d)) {
			dirs = append(dirs, d)
		}
	}
	s.logf("[host] searching for php binaries/modules in: %s", strings.Join(dirs, " "))
	for _, d := range dirs {
		s.walk(s.host(d), nil)
	}
	if len(s.findings) == before {
		s.logf("  nothing found on the host")
	}
}

func (s *scanner) rpmQuery(rpm string) {
	s.dbs.Add(1)
	out, err := exec.Command(rpm, "-qa", "--qf", `%{NAME} %{VERSION}-%{RELEASE}\n`).Output()
	if err != nil {
		s.logf("  WARNING: rpm -qa failed: %v", err)
		return
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(strings.ToLower(l), "php") {
			s.hit("rpm", l, "rpm -qa")
		}
	}
}

// --- containers

type store struct {
	path   string
	layers []string // layer directories: each entry inside is one layer
	images string   // what images were counted, for the log
}

func (s *scanner) scanContainers(extra []string) {
	s.phase.Store("finding storage")
	s.logf("")
	s.logf("[containers] storage roots:")
	var stores []store
	seen := map[string]bool{}
	add := func(label, p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		s.logf("  found   %s", label)
		stores = append(stores, store{path: p})
	}
	for _, r := range storageRoots {
		matches, _ := filepath.Glob(s.host(r))
		if len(matches) == 0 && !strings.Contains(r, "*") {
			s.logf("  missing %s", r)
		}
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && fi.IsDir() {
				add(s.rel(m), m)
			}
		}
	}
	for _, r := range extra {
		p := r
		if !strings.HasPrefix(filepath.Clean(r)+"/", s.root+"/") || s.onHost {
			p = s.host(r)
		}
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			add(s.rel(p)+" (from the command line)", p)
		} else {
			s.logf("  missing %s (from the command line)", r)
		}
	}
	if len(stores) == 0 {
		s.logf("  no container storage on this host")
		return
	}

	// Layer and image counts first, so the progress line can show layer n/N.
	for i := range stores {
		st := &stores[i]
		st.layers = findLayerDirs(st.path)
		st.images = countImages(st.path)
		s.layerDirs = append(s.layerDirs, st.layers...)
		n := 0
		for _, l := range st.layers {
			n += countLayers(l)
		}
		s.layersAll.Add(int64(n))
	}

	for _, st := range stores {
		s.logf("")
		var parts []string
		for _, l := range st.layers {
			rel, _ := filepath.Rel(st.path, l)
			parts = append(parts, fmt.Sprintf("%d layers in %s", countLayers(l), rel))
		}
		if len(parts) == 0 {
			parts = append(parts, "no known layer directory, scanning the whole tree")
		}
		s.logf("[containers] %s: %s; %s", s.rel(st.path), strings.Join(parts, ", "), st.images)
		owners, chains := dockerOwners(st.path)
		if owners != nil {
			s.logf("  mapped %d layers to %d images and their containers", len(owners), len(chains))
		}

		s.phase.Store("containers " + s.rel(st.path))
		before := len(s.findings)
		dbsBefore := s.dbs.Load()
		s.grouping = owners != nil
		if len(st.layers) == 0 {
			s.walk(st.path, nil)
		}
		for _, l := range st.layers {
			s.walk(l, map[string]bool{l: true})
		}
		s.grouping = false
		s.logf("  read %d package dbs", s.dbs.Load()-dbsBefore)
		switch {
		case len(s.findings) == before:
			s.logf("  nothing found")
		case owners != nil:
			s.reportImages(s.findings[before:], owners, chains)
		default:
			s.tally.other += len(s.findings) - before
		}
	}
}

// findLayerDirs finds docker overlay2, containerd overlayfs snapshots (also
// inside /var/lib/docker with Docker's containerd image store) and podman
// overlay directories.
func findLayerDirs(root string) []string {
	var out []string
	base := strings.Count(root, string(os.PathSeparator))
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if strings.Count(p, string(os.PathSeparator))-base > 5 {
			return fs.SkipDir
		}
		switch {
		case d.Name() == "overlay2" && !strings.HasSuffix(p, "/image/overlay2"), // image/overlay2 is docker's metadata
			strings.HasSuffix(p, "/io.containerd.snapshotter.v1.overlayfs/snapshots"),
			d.Name() == "overlay" && strings.HasSuffix(filepath.Dir(p), "storage"):
			out = append(out, p)
			return fs.SkipDir
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func countLayers(dir string) int {
	n := 0
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() && e.Name() != "l" { // overlay2/l holds short-name symlinks
			n++
		}
	}
	return n
}

// countImages counts images from each runtime's own metadata.
func countImages(root string) string {
	var parts []string
	if n := countEntries(filepath.Join(root, "image/overlay2/imagedb/content/sha256")); n >= 0 {
		parts = append(parts, fmt.Sprintf("%d docker images", n))
	}
	if b, err := os.ReadFile(filepath.Join(root, "overlay-images/images.json")); err == nil {
		var imgs []json.RawMessage
		if json.Unmarshal(b, &imgs) == nil {
			parts = append(parts, fmt.Sprintf("%d podman images", len(imgs)))
		}
	}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, "/io.containerd.content.v1.content/blobs/sha256") {
			where := "the content store"
			if rel, err := filepath.Rel(root, filepath.Dir(filepath.Dir(filepath.Dir(p)))); err == nil && rel != "." {
				where = rel
			}
			parts = append(parts, fmt.Sprintf("%d image manifests in %s", countManifests(p), where))
			return fs.SkipDir
		}
		if strings.Count(p, "/")-strings.Count(root, "/") > 5 || d.Name() == "overlay2" || strings.HasSuffix(p, "snapshots") {
			return fs.SkipDir
		}
		return nil
	})
	if len(parts) == 0 {
		return "no image metadata found"
	}
	return strings.Join(parts, ", ")
}

func countEntries(dir string) int {
	e, err := os.ReadDir(dir)
	if err != nil {
		return -1
	}
	return len(e)
}

// countManifests counts single-platform image manifests among containerd's
// content blobs (indexes, attestations, configs and layers are skipped).
func countManifests(dir string) int {
	n := 0
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil || fi.Size() > 1<<20 {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || len(b) == 0 || b[0] != '{' {
			continue
		}
		var m struct {
			MediaType string `json:"mediaType"`
			Config    struct {
				MediaType string `json:"mediaType"`
			} `json:"config"`
			Layers json.RawMessage `json:"layers"`
		}
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		// An image's config is an image config; attestations and other
		// artifacts have their own config types.
		c := m.Config.MediaType
		if m.Layers != nil && (strings.Contains(c, "image.config") || strings.Contains(c, "container.image")) {
			n++
		}
	}
	return n
}

// --- walking

// walk visits every file under dir without following symlinks. layerParents
// marks directories whose children are layers, for the layer counter.
func (s *scanner) walk(dir string, layerParents map[string]bool) {
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable: skip, keep going
		}
		if d.IsDir() {
			s.dirs.Add(1)
			parent := filepath.Dir(p)
			if layerParents[parent] {
				if d.Name() == "l" {
					return fs.SkipDir
				}
				s.layersDone.Add(1)
			}
			// A running Docker container's merged view repeats its layers.
			if d.Name() == "merged" && layerParents[filepath.Dir(parent)] {
				return fs.SkipDir
			}
			return nil
		}
		s.files.Add(1)
		s.checkEntry(p, d)
		return nil
	})
}

func (s *scanner) checkEntry(p string, d fs.DirEntry) {
	name := d.Name()
	switch {
	case strings.HasSuffix(p, "/var/lib/dpkg/status"), strings.HasSuffix(p, "/lib/apk/db/installed"):
		s.checkFile(p)
	case strings.Contains(p, "/var/lib/rpm/") || strings.Contains(p, "/usr/lib/sysimage/rpm/"):
		if d.Type().IsRegular() {
			s.rpmGrep(p)
		}
	case modName.MatchString(name):
		if d.Type().IsRegular() {
			if v, ok := s.phpVersion(p); ok {
				s.hit("module", name+"  "+v, p)
			}
		}
	case binName.MatchString(name):
		if !d.Type().IsRegular() {
			return
		}
		fi, err := d.Info()
		if err != nil || fi.Mode().Perm()&0o100 == 0 {
			return
		}
		v, ok := s.phpVersion(p)
		if !ok {
			return
		}
		what := name + "  " + v
		// Only the host's own PHP is run, and only once it's known to be PHP:
		// never anything from container storage.
		if s.onHost && s.inHost && v != "(unreadable)" && !storagePath.MatchString(p) {
			if out, err := exec.Command(p, "-v").Output(); err == nil && len(bytes.TrimSpace(out)) > 0 {
				what += "  (" + firstLine(out) + ")"
			}
		}
		s.hit("binary", what, p)
	}
}

// PHP's core (main/SAPI.c) has the literal "X-Powered-By: PHP/" PHP_VERSION,
// so every php, php-fpm, php-cgi and libphp/mod_php build carries its version
// without having to run it.
// Container layers that can sit under a host directory (a Docker data-root
// in /srv, say). Nothing under them is ever run.
var storagePath = regexp.MustCompile(`/(overlay2|overlay|snapshots|containers/storage|docker|containerd)/`)

var poweredBy = regexp.MustCompile(`X-Powered-By: PHP/([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+~-]*)`)

// phpVersion reads a file's embedded PHP version. ok is false for a file that
// is only named like PHP (a script, man page or package hook): it's counted
// as skipped, not reported.
func (s *scanner) phpVersion(p string) (v string, ok bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "(unreadable)", true
	}
	if v = versionIn(b); v == "" {
		s.skipped.Add(1)
		return "", false
	}
	return v, true
}

func versionIn(b []byte) string {
	if m := poweredBy.FindSubmatch(b); m != nil {
		return "PHP " + string(m[1])
	}
	return ""
}

func firstLine(b []byte) string {
	l, _, _ := bytes.Cut(b, []byte("\n"))
	return strings.TrimSpace(string(l))
}

// checkFile reads a dpkg status or apk installed database.
func (s *scanner) checkFile(p string) {
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	s.dbs.Add(1)
	kind := "dpkg"
	if strings.HasSuffix(p, "/apk/db/installed") {
		kind = "apk"
	}
	var pkg, status string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		switch {
		case l == "":
			pkg, status = "", ""
		case kind == "dpkg" && strings.HasPrefix(l, "Package: "):
			pkg = l[9:]
		case kind == "dpkg" && strings.HasPrefix(l, "Status: "):
			status = l[8:]
		case kind == "dpkg" && strings.HasPrefix(l, "Version: "):
			if strings.Contains(pkg, "php") && strings.HasSuffix(status, " installed") {
				s.hit(kind, pkg+" "+l[9:], p)
			}
		case kind == "apk" && strings.HasPrefix(l, "P:"):
			pkg = l[2:]
		case kind == "apk" && strings.HasPrefix(l, "V:"):
			if strings.Contains(pkg, "php") {
				s.hit(kind, pkg+" "+l[2:], p)
			}
		}
	}
}

// rpmGrep matches package names in an rpm database file, which can't be read
// without rpm (bdb or sqlite).
func (s *scanner) rpmGrep(p string) {
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	s.dbs.Add(1)
	for _, n := range []string{"php-cli", "php-fpm", "php-common", "mod_php"} {
		if bytes.Contains(b, []byte(n)) {
			s.hit("rpm", "database mentions "+n+" (no version)", p)
			return
		}
	}
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
