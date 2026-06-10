module github.com/baseproof/tooling/e2e

go 1.25.7

require (
	github.com/baseproof/baseproof v0.0.4-rc2
	github.com/baseproof/tooling/libs v0.0.0-00010101000000-000000000000
)

replace github.com/baseproof/tooling/libs => ../libs
