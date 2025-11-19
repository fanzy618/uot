package version

// Build metadata filled via -ldflags at build time.
var (
    Version   = "dev"
    GitCommit = "unknown"
    BuildTime = "unknown"
)
