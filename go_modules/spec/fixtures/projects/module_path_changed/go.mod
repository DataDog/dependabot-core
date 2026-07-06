module github.com/dependabot/vgotest

go 1.12

require (
	github.com/Sirupsen/logrus v1.3.0
	// The actual repo is fatih/color, but including the capital
	// helps us test that we preserve caps
	github.com/fatih/Color v1.7.0
	github.com/mattn/go-colorable v0.0.9
	github.com/mattn/go-isatty v0.0.4
	golang.org/x/sys v0.46.0 // indirect
	rsc.io/qr v0.1.0
)

replace rsc.io/qr => github.com/rsc/qr v0.2.0
