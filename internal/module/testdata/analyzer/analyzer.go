//go:generate go build -o analyzer.wasm -buildmode=c-shared analyzer.go
//go:build wasip1

package main

import (
	"github.com/aquasecurity/trivy/internal/module/serialize"
	"github.com/aquasecurity/trivy/internal/module/wasm"
)

const (
	moduleVersion = 1
	moduleName    = "analyzer"
)

func main() {}

func init() {
	wasm.RegisterModule(AnalyzerModule{})
}

type AnalyzerModule struct{}

func (AnalyzerModule) Version() int {
	return moduleVersion
}

func (AnalyzerModule) Name() string {
	return moduleName
}

func (AnalyzerModule) RequiredFiles() []string {
	return []string{
		`foo(.?)`,
	}
}

func (s AnalyzerModule) Analyze(_ string) (*serialize.AnalysisResult, error) {
	return nil, nil
}
