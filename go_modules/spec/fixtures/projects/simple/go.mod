module github.com/dependabot/vgotest

go 1.25.0

require (
	// The actual repo is fatih/color, but including the capital
	// helps us test that we preserve caps
	github.com/fatih/Color v1.7.0
	github.com/mattn/go-isatty v0.0.4
	rsc.io/qr v0.1.0
	rsc.io/quote v1.4.0
)

require (
	github.com/mattn/go-colorable v0.0.9 // indirect
	golang.org/x/sys v0.46.0 // indirect
	rsc.io/sampler v1.0.0 // indirect
)

replace rsc.io/qr => github.com/rsc/qr v0.2.0
