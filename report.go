package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// tally counts what the RESULT line reports.
type tally struct {
	host       int
	images     int // images that run PHP
	allGone    int // images whose every copy a later layer replaces or removes
	containers int
	unused     int
	other      int
}

func (t tally) String() string {
	var parts []string
	if t.host > 0 {
		parts = append(parts, fmt.Sprintf("%d on the host", t.host))
	}
	if t.images > 0 {
		parts = append(parts, fmt.Sprintf("%d image(s) with PHP", t.images))
	}
	if t.allGone > 0 {
		parts = append(parts, fmt.Sprintf("%d image(s) where a later layer replaced or removed it", t.allGone))
	}
	if t.containers > 0 {
		parts = append(parts, fmt.Sprintf("%d container(s) added PHP in their own layer", t.containers))
	}
	if t.unused > 0 {
		parts = append(parts, fmt.Sprintf("%d in layers no image or container uses", t.unused))
	}
	if t.other > 0 {
		parts = append(parts, fmt.Sprintf("%d in other container storage", t.other))
	}
	return strings.Join(parts, "; ")
}

// layerOf splits a path in a layer directory into the layer
// (".../overlay2/<id>") and the path inside its tree ("usr/local/bin/php").
func (s *scanner) layerOf(path string) (layer, rel string) {
	for _, l := range s.layerDirs {
		if rest, ok := strings.CutPrefix(path, l+"/"); ok {
			id, inner, _ := strings.Cut(rest, "/")
			_, rel, _ = strings.Cut(inner, "/") // drop diff/ (overlay2, podman) or fs/ (containerd)
			return filepath.Join(l, id), rel
		}
	}
	return "", ""
}

// topLayer is the layer whose copy of rel an image runs: the highest one that
// has anything at rel. "" means a later layer removed it (a whiteout, or a
// file where one of its parent directories was).
func topLayer(chain []string, rel string) string {
	for i := len(chain) - 1; i >= 0; i-- {
		if _, err := os.Lstat(filepath.Join(chain[i], "diff", rel)); err == nil {
			if replacedAbove(chain[i+1:], rel) {
				return ""
			}
			return chain[i]
		}
	}
	return ""
}

// replacedAbove reports whether one of these layers has a non-directory where
// a parent of rel is. Opaque directories (an xattr) aren't checked.
func replacedAbove(upper []string, rel string) bool {
	parts := strings.Split(rel, "/")
	for _, up := range upper {
		p := filepath.Join(up, "diff")
		for _, part := range parts[:len(parts)-1] {
			p = filepath.Join(p, part)
			fi, err := os.Lstat(p)
			if err != nil {
				break
			}
			if !fi.IsDir() {
				return true
			}
		}
	}
	return false
}

// reportImages prints a Docker store's findings by what each image runs, then
// what containers added and what's in layers nothing uses.
func (s *scanner) reportImages(fs []finding, owners, chains map[string][]string) {
	byLayer := map[string][]finding{}
	for _, f := range fs {
		byLayer[f.layer] = append(byLayer[f.layer], f)
	}

	labels := make([]string, 0, len(chains))
	for l := range chains {
		labels = append(labels, l)
	}
	sort.Slice(labels, func(i, j int) bool { // tagged images first
		ui, uj := strings.HasPrefix(labels[i], "untagged "), strings.HasPrefix(labels[j], "untagged ")
		if ui != uj {
			return uj
		}
		return labels[i] < labels[j]
	})

	inImage := map[string]bool{}
	for _, label := range labels {
		chain := chains[label]
		var rels []string
		seen := map[string]bool{}
		for _, l := range chain {
			inImage[l] = true
			for _, f := range byLayer[l] {
				if !seen[f.rel] {
					seen[f.rel] = true
					rels = append(rels, f.rel)
				}
			}
		}
		if len(rels) == 0 {
			continue
		}
		var active, replaced []finding
		for _, rel := range rels {
			top := topLayer(chain, rel)
			for _, l := range chain {
				for _, f := range byLayer[l] {
					if f.rel != rel {
						continue
					}
					if l == top {
						active = append(active, f)
					} else {
						replaced = append(replaced, f)
					}
				}
			}
		}
		if len(active) > 0 {
			s.tally.images++
			s.logf("  image %s", label)
		} else {
			s.tally.allGone++
			s.logf("  image %s: every copy replaced or removed by a later layer", label)
		}
		for _, f := range active {
			s.logf("      %-6s %s  /%s", f.kind, f.what, f.rel)
		}
		for _, f := range replaced {
			s.logf("      replaced or removed later: %-6s %s  /%s", f.kind, f.what, f.rel)
		}
	}

	containers := map[string][]finding{}
	var unused []finding
	for _, f := range fs {
		if inImage[f.layer] {
			continue
		}
		o := owners[f.layer]
		if len(o) == 0 {
			unused = append(unused, f)
		}
		for _, owner := range o {
			containers[owner] = append(containers[owner], f)
		}
	}
	names := make([]string, 0, len(containers))
	for n := range containers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s.tally.containers++
		s.logf("  %s", n)
		for _, f := range containers[n] {
			s.logf("      %-6s %s  /%s", f.kind, f.what, f.rel)
		}
	}
	if len(unused) > 0 {
		s.tally.unused += len(unused)
		s.logf("  not in any image or container (build cache, or layers of deleted images):")
		for _, f := range unused {
			s.logf("      %-6s %s  (%s)", f.kind, f.what, s.rel(f.path))
		}
	}
}
