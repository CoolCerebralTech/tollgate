package policy

// LoaderStatus exposes the current policy load state for the health endpoint.
// Returns (version, hash, isValid).
func (e *Engine) LoaderStatus() (version, hash string, valid bool) {
	p, h, v := e.loader.GetPolicy()
	if p == nil {
		return "", h, v
	}
	return p.Version, h, v
}
