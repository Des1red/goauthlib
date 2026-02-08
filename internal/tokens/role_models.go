package tokens

// Defaults (compile-time, safe)
const (
	DefaultRoleAnonymous = "anonymous"
	DefaultRoleUser      = "user"
	DefaultRoleAdmin     = "admin"
)

// Runtime role config (read-only outside tokens)
type Roles struct {
	Anonymous string
	User      string
	Admin     string
}

var rolesCfg = Roles{
	Anonymous: DefaultRoleAnonymous,
	User:      DefaultRoleUser,
	Admin:     DefaultRoleAdmin,
}

// Optional: called by host app
func SetRoles(cfg Roles) {
	if cfg.Anonymous == "" {
		cfg.Anonymous = rolesCfg.Anonymous
	}
	if cfg.User == "" {
		cfg.User = rolesCfg.User
	}
	if cfg.Admin == "" {
		cfg.Admin = rolesCfg.Admin
	}

	rolesCfg = cfg
}

func RoleAnonymous() string {
	return rolesCfg.Anonymous
}

func RoleUser() string {
	return rolesCfg.User
}

func RoleAdmin() string {
	return rolesCfg.Admin
}
