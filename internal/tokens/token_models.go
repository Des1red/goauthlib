package tokens

import "time"

// Defaults
const (
	DefaultAccessTTL    = 10 * time.Minute
	DefaultAnonymousTTL = 5 * time.Minute
	DefaultRefreshTTL   = 24 * time.Hour
)

// Runtime config (used everywhere internally)
type TokenConfig struct {
	AccessTTL    time.Duration
	AnonymousTTL time.Duration
	RefreshTTL   time.Duration
}

var tokenCfg = TokenConfig{
	AccessTTL:    DefaultAccessTTL,
	AnonymousTTL: DefaultAnonymousTTL,
	RefreshTTL:   DefaultRefreshTTL,
}

// Called by host app (optional)
func SetTokenConfig(cfg TokenConfig) {
	// fill zero values with defaults
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = tokenCfg.AccessTTL
	}
	if cfg.AnonymousTTL <= 0 {
		cfg.AnonymousTTL = tokenCfg.AnonymousTTL
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = tokenCfg.RefreshTTL
	}

	// safety clamps
	if cfg.AccessTTL < 30*time.Second {
		cfg.AccessTTL = 30 * time.Second
	}
	if cfg.RefreshTTL < time.Hour {
		cfg.RefreshTTL = time.Hour
	}

	tokenCfg = cfg
}

func AccessTTL() time.Duration {
	return tokenCfg.AccessTTL
}

func RefreshTTL() time.Duration {
	return tokenCfg.RefreshTTL
}

func AnonymousTTL() time.Duration {
	return tokenCfg.AnonymousTTL
}
