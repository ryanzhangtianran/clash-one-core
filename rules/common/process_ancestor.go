package common

import (
	"path/filepath"
	"strings"

	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
)

// ProcessAncestor matches when the connection's process or any of its ancestors has the given
// executable name (PROCESS-ANCESTOR) or path (PROCESS-ANCESTOR-PATH), e.g. everything started in a terminal.
type ProcessAncestor struct {
	Base
	pattern  string
	adapter  string
	ruleType C.RuleType
}

func (pa *ProcessAncestor) Payload() string      { return pa.pattern }
func (pa *ProcessAncestor) Adapter() string      { return pa.adapter }
func (pa *ProcessAncestor) RuleType() C.RuleType { return pa.ruleType }

func (pa *ProcessAncestor) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if helper.FindProcess != nil {
		helper.FindProcess()
	}
	// ponytail: walks the live chain on every evaluation (a few syscalls); cache on metadata if rule sets grow
	ancestors, _ := process.Ancestors(metadata.Pid) // pid 0 (unknown) yields none
	for _, path := range append([]string{metadata.ProcessPath}, ancestors...) {
		if pa.match(path) {
			return true, pa.adapter
		}
	}
	return false, pa.adapter
}

func (pa *ProcessAncestor) match(path string) bool {
	if path == "" {
		return false
	}
	if pa.ruleType == C.ProcessAncestorPath {
		return strings.EqualFold(path, pa.pattern)
	}
	return strings.EqualFold(filepath.Base(path), pa.pattern)
}

func NewProcessAncestor(pattern string, adapter string, ruleType C.RuleType) (*ProcessAncestor, error) {
	return &ProcessAncestor{pattern: pattern, adapter: adapter, ruleType: ruleType}, nil
}

var _ C.Rule = (*ProcessAncestor)(nil)
