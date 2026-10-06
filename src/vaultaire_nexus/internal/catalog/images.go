package catalog

import (
	"errors"
	"sort"
	"time"

	"vaultaire_nexus/internal/config"
)

// ErrManifestUnknown : ni tag ni condensat connu.
var ErrManifestUnknown = errors.New("manifeste inconnu")

func (c *Catalog) dockerRepo(repo string) (*repoFile, error) {
	rf, ok := c.repos[repo]
	if !ok {
		return nil, ErrRepoNotFound
	}
	if rf.Repo.Type != config.RepoDocker {
		return nil, ErrWrongType
	}
	return rf, nil
}

// PutManifest enregistre un manifeste, et l'étiquette si tag != "".
func (c *Catalog) PutManifest(repo, image, tag string, m Manifest) error {
	c.mu.Lock()
	rf, err := c.dockerRepo(repo)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	im, ok := rf.Images[image]
	if !ok {
		im = &Image{Name: image, Tags: map[string]string{}, Manifests: map[string]Manifest{}}
		rf.Images[image] = im
	}
	if old, ok := im.Manifests[m.Digest]; ok {
		m.PushedAt = old.PushedAt // repousser le même contenu ne le rajeunit pas
	} else {
		m.PushedAt = time.Now().UTC()
	}
	im.Manifests[m.Digest] = m
	if tag != "" {
		im.Tags[tag] = m.Digest
	}
	im.UpdatedAt = time.Now().UTC()
	out, err := c.changed(rf)
	c.mu.Unlock()
	if err == nil {
		c.notify(out)
	}
	return err
}

// ResolveManifest rend le manifeste désigné par un tag ou un condensat.
func (c *Catalog) ResolveManifest(repo, image, ref string) (Manifest, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rf, err := c.dockerRepo(repo)
	if err != nil {
		return Manifest{}, err
	}
	im, ok := rf.Images[image]
	if !ok {
		return Manifest{}, ErrManifestUnknown
	}
	if d, ok := im.Tags[ref]; ok {
		ref = d
	}
	m, ok := im.Manifests[ref]
	if !ok {
		return Manifest{}, ErrManifestUnknown
	}
	return m, nil
}

// HasManifest dit si un condensat est un manifeste de l'image.
func (c *Catalog) HasManifest(repo, image, digest string) bool {
	_, err := c.ResolveManifest(repo, image, digest)
	return err == nil
}

// DeleteManifest retire un manifeste (par condensat) et les tags qui le visent,
// ou seulement un tag si ref n'est pas un condensat.
func (c *Catalog) DeleteManifest(repo, image, ref string) error {
	c.mu.Lock()
	rf, err := c.dockerRepo(repo)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	im, ok := rf.Images[image]
	if !ok {
		c.mu.Unlock()
		return ErrManifestUnknown
	}
	if _, isTag := im.Tags[ref]; isTag {
		delete(im.Tags, ref)
	} else {
		if _, ok := im.Manifests[ref]; !ok {
			c.mu.Unlock()
			return ErrManifestUnknown
		}
		delete(im.Manifests, ref)
		for t, d := range im.Tags {
			if d == ref {
				delete(im.Tags, t)
			}
		}
	}
	if len(im.Manifests) == 0 {
		delete(rf.Images, image)
	}
	out, err := c.changed(rf)
	c.mu.Unlock()
	if err == nil {
		c.notify(out)
	}
	return err
}

// Images rend les images d'un dépôt, triées.
func (c *Catalog) Images(repo string) []Image {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rf, ok := c.repos[repo]
	if !ok {
		return nil
	}
	out := make([]Image, 0, len(rf.Images))
	for _, im := range rf.Images {
		out = append(out, copyImage(im))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Image rend une image.
func (c *Catalog) Image(repo, name string) (Image, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rf, ok := c.repos[repo]
	if !ok {
		return Image{}, ErrRepoNotFound
	}
	im, ok := rf.Images[name]
	if !ok {
		return Image{}, ErrManifestUnknown
	}
	return copyImage(im), nil
}

// ImageBlobKnown dit si un blob appartient déjà à une image du dépôt
// (contrôle d'accès des montages entre dépôts).
func (c *Catalog) ImageBlobKnown(repo, image, digest string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rf, err := c.dockerRepo(repo)
	if err != nil {
		return false
	}
	im, ok := rf.Images[image]
	if !ok {
		return false
	}
	for d, m := range im.Manifests {
		if d == digest {
			return true
		}
		for _, r := range m.Refs {
			if r == digest {
				return true
			}
		}
	}
	return false
}

func copyImage(im *Image) Image {
	cp := Image{Name: im.Name, UpdatedAt: im.UpdatedAt, Tags: map[string]string{}, Manifests: map[string]Manifest{}}
	for k, v := range im.Tags {
		cp.Tags[k] = v
	}
	for k, v := range im.Manifests {
		cp.Manifests[k] = v
	}
	return cp
}

// TagList rend les tags triés d'une image.
func (im Image) TagList() []string {
	out := make([]string, 0, len(im.Tags))
	for t := range im.Tags {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
