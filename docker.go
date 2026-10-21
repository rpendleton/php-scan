package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// dockerOwners maps each overlay2 layer directory of a Docker data root to the
// images and containers that use it, from Docker's own metadata:
// image/overlay2/imagedb holds image configs (their layers as diff IDs),
// layerdb maps chain IDs to overlay2 directories (cache-id) and containers to
// their writable layers (mounts/<id>/mount-id), and repositories.json holds
// the tags. It also returns each image's layer directories, bottom first.
func dockerOwners(store string) (owners, chains map[string][]string) {
	meta := filepath.Join(store, "image/overlay2")
	if !exists(meta) {
		return nil, nil
	}
	owners, chains = map[string][]string{}, map[string][]string{}
	add := func(dir, owner string) {
		p := filepath.Join(store, "overlay2", dir)
		for _, o := range owners[p] {
			if o == owner {
				return
			}
		}
		owners[p] = append(owners[p], owner)
	}

	cacheIDs := map[string]string{} // chain ID -> overlay2 directory
	entries, _ := os.ReadDir(filepath.Join(meta, "layerdb/sha256"))
	for _, e := range entries {
		if b, err := os.ReadFile(filepath.Join(meta, "layerdb/sha256", e.Name(), "cache-id")); err == nil {
			cacheIDs["sha256:"+e.Name()] = strings.TrimSpace(string(b))
		}
	}

	tags := map[string][]string{} // image ID -> tags
	if b, err := os.ReadFile(filepath.Join(meta, "repositories.json")); err == nil {
		var r struct{ Repositories map[string]map[string]string }
		if json.Unmarshal(b, &r) == nil {
			for _, refs := range r.Repositories {
				for ref, id := range refs {
					if !strings.Contains(ref, "@") {
						tags[id] = append(tags[id], ref)
					}
				}
			}
		}
	}

	imageLabels := map[string]string{}
	entries, _ = os.ReadDir(filepath.Join(meta, "imagedb/content/sha256"))
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(meta, "imagedb/content/sha256", e.Name()))
		if err != nil {
			continue
		}
		var img struct {
			RootFS struct {
				DiffIDs []string `json:"diff_ids"`
			} `json:"rootfs"`
		}
		if json.Unmarshal(b, &img) != nil {
			continue
		}
		id := "sha256:" + e.Name()
		label := "untagged " + e.Name()[:12]
		if t := tags[id]; len(t) > 0 {
			sort.Strings(t)
			label = strings.Join(t, ", ")
		}
		imageLabels[id] = label
		chain := ""
		for _, diff := range img.RootFS.DiffIDs {
			if chain == "" {
				chain = diff
			} else {
				sum := sha256.Sum256([]byte(chain + " " + diff))
				chain = "sha256:" + hex.EncodeToString(sum[:])
			}
			if dir, ok := cacheIDs[chain]; ok {
				add(dir, "image "+label)
				chains[label] = append(chains[label], filepath.Join(store, "overlay2", dir))
			}
		}
	}

	entries, _ = os.ReadDir(filepath.Join(meta, "layerdb/mounts"))
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(meta, "layerdb/mounts", e.Name(), "mount-id"))
		if err != nil {
			continue
		}
		mount := strings.TrimSpace(string(b))
		name := e.Name()[:12]
		image := ""
		if b, err := os.ReadFile(filepath.Join(store, "containers", e.Name(), "config.v2.json")); err == nil {
			var c struct {
				Name   string
				Image  string
				Config struct{ Image string }
			}
			if json.Unmarshal(b, &c) == nil {
				name = strings.TrimPrefix(c.Name, "/")
				image = c.Config.Image
				if image == "" {
					image = imageLabels[c.Image]
				}
			}
		}
		desc := "container " + name
		if image != "" {
			desc += " (" + image + ")"
		}
		add(mount, desc+" writable layer")
		add(mount+"-init", desc+" init layer")
	}
	return owners, chains
}
