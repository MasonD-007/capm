module github.com/MasonD-007/capm/cli

go 1.27.3

require (
	github.com/MasonD-007/capm/manifest v0.0.0
	golang.org/x/term v0.46.0
	gopkg.in/yaml.v3 v3.0.1
)

require golang.org/x/sys v0.48.0 // indirect

replace github.com/MasonD-007/capm/manifest => ../manifest
