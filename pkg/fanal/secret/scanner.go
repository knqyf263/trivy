package secret

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

var lineSep = []byte{'\n'}

const (
	DefaultBufferSize = 64 * 1024 // 64KB default buffer size
	DefaultOverlap    = 2048      // 2KB overlap for boundary handling
)

type Scanner struct {
	logger     *log.Logger
	bufferSize int
	*Global
}

type Config struct {
	// Enable only specified built-in rules. If only one ID is specified, all other rules are disabled.
	// All the built-in rules are enabled if this field is not specified. It doesn't affect custom rules.
	EnableBuiltinRuleIDs []string `yaml:"enable-builtin-rules"`

	// Disable rules. It is applied to enabled IDs.
	DisableRuleIDs []string `yaml:"disable-rules"`

	// Disable allow rules.
	DisableAllowRuleIDs []string `yaml:"disable-allow-rules"`

	CustomRules      []Rule       `yaml:"rules"`
	CustomAllowRules AllowRules   `yaml:"allow-rules"`
	ExcludeBlock     ExcludeBlock `yaml:"exclude-block"`
}

type Global struct {
	Rules        []Rule
	AllowRules   AllowRules
	ExcludeBlock ExcludeBlock
}

// Allow checks if the match is allowed
func (g Global) Allow(match string) bool {
	return g.AllowRules.Allow(match)
}

// AllowPath checks if the path is allowed
func (g Global) AllowPath(path string) bool {
	return g.AllowRules.AllowPath(path)
}

// Regexp adds unmarshalling from YAML for regexp.Regexp
type Regexp struct {
	*regexp.Regexp
}

func MustCompileWithoutWordPrefix(str string) *Regexp {
	return MustCompile(fmt.Sprintf("%s(%s)", startWord, str))
}

func MustCompile(str string) *Regexp {
	return &Regexp{regexp.MustCompile(str)}
}

// UnmarshalYAML unmarshals YAML into a regexp.Regexp
func (r *Regexp) UnmarshalYAML(value *yaml.Node) error {
	var v string
	if err := value.Decode(&v); err != nil {
		return err
	}
	regex, err := regexp.Compile(v)
	if err != nil {
		return xerrors.Errorf("regexp compile error: %w", err)
	}

	r.Regexp = regex
	return nil
}

type Rule struct {
	ID              string                   `yaml:"id"`
	Category        types.SecretRuleCategory `yaml:"category"`
	Title           string                   `yaml:"title"`
	Severity        string                   `yaml:"severity"`
	Regex           *Regexp                  `yaml:"regex"`
	Keywords        []string                 `yaml:"keywords"`
	Path            *Regexp                  `yaml:"path"`
	AllowRules      AllowRules               `yaml:"allow-rules"`
	ExcludeBlock    ExcludeBlock             `yaml:"exclude-block"`
	SecretGroupName string                   `yaml:"secret-group-name"`
}

func (s *Scanner) FindLocations(r Rule, content []byte) []Location {
	if r.Regex == nil {
		return nil
	}

	if r.SecretGroupName != "" {
		return s.FindSubmatchLocations(r, content)
	}

	var locs []Location
	indices := r.Regex.FindAllIndex(content, -1)
	for _, index := range indices {
		loc := Location{
			Start: index[0],
			End:   index[1],
		}

		if s.AllowLocation(r, content, loc) {
			continue
		}

		locs = append(locs, loc)
	}
	return locs
}

func (s *Scanner) FindSubmatchLocations(r Rule, content []byte) []Location {
	var submatchLocations []Location
	matchsIndices := r.Regex.FindAllSubmatchIndex(content, -1)
	for _, matchIndices := range matchsIndices {
		matchLocation := Location{
			// first two indexes are always start and end of the whole match
			Start: matchIndices[0],
			End:   matchIndices[1],
		}

		if s.AllowLocation(r, content, matchLocation) {
			continue
		}

		matchSubgroupsLocations := r.getMatchSubgroupsLocations(matchIndices)
		if len(matchSubgroupsLocations) > 0 {
			submatchLocations = append(submatchLocations, matchSubgroupsLocations...)
		}
	}
	return submatchLocations
}

func (s *Scanner) AllowLocation(r Rule, content []byte, loc Location) bool {
	match := string(content[loc.Start:loc.End])
	return s.Allow(match) || r.Allow(match)
}

func (r *Rule) getMatchSubgroupsLocations(matchLocs []int) []Location {
	var locations []Location
	for i, name := range r.Regex.SubexpNames() {
		if name == r.SecretGroupName {
			startLocIndex := 2 * i
			endLocIndex := startLocIndex + 1
			locations = append(locations, Location{
				Start: matchLocs[startLocIndex],
				End:   matchLocs[endLocIndex],
			})
		}
	}
	return locations
}

func (r *Rule) MatchPath(path string) bool {
	return r.Path == nil || r.Path.MatchString(path)
}

func (r *Rule) MatchKeywords(content []byte) bool {
	if len(r.Keywords) == 0 {
		return true
	}
	contentLower := bytes.ToLower(content)
	for _, kw := range r.Keywords {
		if bytes.Contains(contentLower, []byte(strings.ToLower(kw))) {
			return true
		}
	}

	return false
}

func (r *Rule) AllowPath(path string) bool {
	return r.AllowRules.AllowPath(path)
}

func (r *Rule) Allow(match string) bool {
	return r.AllowRules.Allow(match)
}

type AllowRule struct {
	ID          string  `yaml:"id"`
	Description string  `yaml:"description"`
	Regex       *Regexp `yaml:"regex"`
	Path        *Regexp `yaml:"path"`
}

type AllowRules []AllowRule

func (rules AllowRules) AllowPath(path string) bool {
	for _, rule := range rules {
		if rule.Path != nil && rule.Path.MatchString(path) {
			return true
		}
	}
	return false
}

func (rules AllowRules) Allow(match string) bool {
	for _, rule := range rules {
		if rule.Regex != nil && rule.Regex.MatchString(match) {
			return true
		}
	}
	return false
}

type ExcludeBlock struct {
	Description string    `yaml:"description"`
	Regexes     []*Regexp `yaml:"regexes"`
}

type Location struct {
	Start int
	End   int
}

func (l Location) Match(loc Location) bool {
	return l.Start <= loc.Start && loc.End <= l.End
}

type Blocks struct {
	content []byte
	regexes []*Regexp
	locs    []Location
	once    *sync.Once
}

func newBlocks(content []byte, regexes []*Regexp) Blocks {
	return Blocks{
		content: content,
		regexes: regexes,
		once:    new(sync.Once),
	}
}

func (b *Blocks) Match(block Location) bool {
	b.once.Do(b.find)
	for _, loc := range b.locs {
		if loc.Match(block) {
			return true
		}
	}
	return false
}

func (b *Blocks) find() {
	for _, regex := range b.regexes {
		results := regex.FindAllIndex(b.content, -1)
		if len(results) == 0 {
			continue
		}
		for _, r := range results {
			b.locs = append(b.locs, Location{
				Start: r[0],
				End:   r[1],
			})
		}
	}
}

func ParseConfig(configPath string) (*Config, error) {
	// If no config is passed, use built-in rules and allow rules.
	if configPath == "" {
		return nil, nil
	}

	logger := log.WithPrefix("secret").With("config_path", configPath)
	f, err := os.Open(configPath)
	if errors.Is(err, os.ErrNotExist) {
		// If the specified file doesn't exist, it just uses built-in rules and allow rules.
		logger.Debug("No secret config detected")
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf("file open error %s: %w", configPath, err)
	}
	defer f.Close()

	logger.Info("Loading the config file for secret scanning...")

	var config Config
	if err = yaml.NewDecoder(f).Decode(&config); err != nil {
		return nil, xerrors.Errorf("secrets config decode error: %w", err)
	}

	// Update severity for custom rules
	for i := range config.CustomRules {
		config.CustomRules[i].Severity = convertSeverity(logger, config.CustomRules[i].Severity)
	}

	return &config, nil
}

// convertSeverity checks the severity and converts it to uppercase or uses "UNKNOWN" for the wrong severity.
func convertSeverity(logger *log.Logger, severity string) string {
	switch strings.ToLower(severity) {
	case "low", "medium", "high", "critical", "unknown":
		return strings.ToUpper(severity)
	default:
		logger.Warn("Incorrect severity", log.String("severity", severity))
		return "UNKNOWN"
	}
}

func NewScanner(config *Config) Scanner {
	logger := log.WithPrefix("secret")

	// Use the default rules
	if config == nil {
		return Scanner{
			logger:     logger,
			bufferSize: DefaultBufferSize,
			Global: &Global{
				Rules:      builtinRules,
				AllowRules: builtinAllowRules,
			},
		}
	}

	enabledRules := builtinRules
	if len(config.EnableBuiltinRuleIDs) != 0 {
		// Enable only specified built-in rules
		enabledRules = lo.Filter(builtinRules, func(v Rule, _ int) bool {
			return slices.Contains(config.EnableBuiltinRuleIDs, v.ID)
		})
	}

	// Custom rules are enabled regardless of "enable-builtin-rules".
	enabledRules = append(enabledRules, config.CustomRules...)

	// Disable specified rules
	rules := lo.Filter(enabledRules, func(v Rule, _ int) bool {
		return !slices.Contains(config.DisableRuleIDs, v.ID)
	})

	// Disable specified allow rules
	allowRules := append(builtinAllowRules, config.CustomAllowRules...)
	allowRules = lo.Filter(allowRules, func(v AllowRule, _ int) bool {
		return !slices.Contains(config.DisableAllowRuleIDs, v.ID)
	})

	return Scanner{
		logger:     logger,
		bufferSize: DefaultBufferSize,
		Global: &Global{
			Rules:        rules,
			AllowRules:   allowRules,
			ExcludeBlock: config.ExcludeBlock,
		},
	}
}

// WithBufferSize configures the buffer size for streaming
func (s Scanner) WithBufferSize(size int) Scanner {
	s.bufferSize = size
	return s
}

// GetBufferSize returns the current buffer size (for testing)
func (s Scanner) GetBufferSize() int {
	return s.bufferSize
}

type ScanArgs struct {
	FilePath string
	Content  io.Reader
	Binary   bool
}

type Match struct {
	Rule     Rule
	Location Location
}

func (s *Scanner) Scan(args ScanArgs) types.Secret {
	logger := s.logger.With("file_path", args.FilePath)

	// Global allowed paths
	if s.AllowPath(args.FilePath) {
		logger.Debug("Skipped secret scanning matching allowed paths")
		return types.Secret{
			FilePath: args.FilePath,
		}
	}

	// Read the entire content from the reader
	content, err := io.ReadAll(args.Content)
	if err != nil {
		logger.Error("Failed to read content", log.Err(err))
		return types.Secret{
			FilePath: args.FilePath,
		}
	}

	// Use streaming approach for processing
	result := s.scanContent(args.FilePath, content, args.Binary)
	return result
}

func (s *Scanner) scanContent(filePath string, content []byte, binary bool) types.Secret {
	// For small files or if buffer size is larger than content, process directly
	if len(content) <= s.bufferSize {
		return s.scanChunk(filePath, content, 0, binary)
	}

	// Stream large files in chunks
	var allFindings []types.SecretFinding
	overlap := DefaultOverlap
	if overlap > s.bufferSize/4 {
		overlap = s.bufferSize / 4
	}

	for offset := 0; offset < len(content); {
		var chunkEnd int
		
		// Determine chunk boundaries
		if offset+s.bufferSize >= len(content) {
			chunkEnd = len(content)
		} else {
			chunkEnd = offset + s.bufferSize
		}

		chunk := content[offset:chunkEnd]
		chunkResult := s.scanChunk(filePath, chunk, offset, binary)
		
		// Merge findings, adjusting line numbers for chunk offset
		for _, finding := range chunkResult.Findings {
			// Adjust line numbers based on chunk offset
			if offset > 0 {
				lineOffset := bytes.Count(content[:offset], lineSep)
				finding.StartLine += lineOffset
				finding.EndLine += lineOffset
				
				// Update code lines
				for i := range finding.Code.Lines {
					finding.Code.Lines[i].Number += lineOffset
				}
			}
			allFindings = append(allFindings, finding)
		}

		// Move to next chunk with overlap handling
		if chunkEnd >= len(content) {
			break
		}
		
		nextOffset := chunkEnd - overlap
		if nextOffset <= offset {
			nextOffset = offset + 1
		}
		offset = nextOffset
	}

	if len(allFindings) == 0 {
		return types.Secret{}
	}

	// Remove duplicate findings that might occur at chunk boundaries
	allFindings = s.deduplicateFindings(allFindings)

	sort.Slice(allFindings, func(i, j int) bool {
		if allFindings[i].RuleID != allFindings[j].RuleID {
			return allFindings[i].RuleID < allFindings[j].RuleID
		}
		return allFindings[i].Match < allFindings[j].Match
	})

	return types.Secret{
		FilePath: filePath,
		Findings: allFindings,
	}
}

func (s *Scanner) scanChunk(filePath string, content []byte, offset int, binary bool) types.Secret {
	logger := s.logger.With("file_path", filePath)

	var censored []byte
	var copyCensored sync.Once
	var matched []Match

	var findings []types.SecretFinding
	globalExcludedBlocks := newBlocks(content, s.ExcludeBlock.Regexes)
	
	for _, rule := range s.Rules {
		ruleLogger := logger.With("rule_id", rule.ID)
		// Check if the file path should be scanned by this rule
		if !rule.MatchPath(filePath) {
			ruleLogger.Debug("Skipped secret scanning as non-compliant to the rule")
			continue
		}

		// Check if the file path should be allowed
		if rule.AllowPath(filePath) {
			ruleLogger.Debug("Skipped secret scanning as allowed")
			continue
		}

		// Check if the file content contains keywords and should be scanned
		if !rule.MatchKeywords(content) {
			continue
		}

		// Detect secrets
		locs := s.FindLocations(rule, content)
		if len(locs) == 0 {
			continue
		}

		localExcludedBlocks := newBlocks(content, rule.ExcludeBlock.Regexes)

		for _, loc := range locs {
			// Skip the secret if it is within excluded blocks.
			if globalExcludedBlocks.Match(loc) || localExcludedBlocks.Match(loc) {
				continue
			}

			matched = append(matched, Match{
				Rule:     rule,
				Location: loc,
			})
			copyCensored.Do(func() {
				censored = make([]byte, len(content))
				copy(censored, content)
			})
			censored = censorLocation(loc, censored)
		}
	}
	
	for _, match := range matched {
		finding := toFinding(match.Rule, match.Location, censored)
		// Rewrite unreadable fields for binary files
		if binary {
			finding.Match = fmt.Sprintf("Binary file %q matches a rule %q", filePath, match.Rule.Title)
			finding.Code = types.Code{}
		}
		findings = append(findings, finding)
	}

	if len(findings) == 0 {
		return types.Secret{}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Match < findings[j].Match
	})

	return types.Secret{
		FilePath: filePath,
		Findings: findings,
	}
}

func (s *Scanner) deduplicateFindings(findings []types.SecretFinding) []types.SecretFinding {
	seen := make(map[string]bool)
	var result []types.SecretFinding
	
	for _, finding := range findings {
		key := fmt.Sprintf("%s:%d:%d:%s", finding.RuleID, finding.StartLine, finding.EndLine, finding.Match)
		if !seen[key] {
			seen[key] = true
			result = append(result, finding)
		}
	}
	
	return result
}

func censorLocation(loc Location, input []byte) []byte {
	for i := loc.Start; i < loc.End; i++ {
		if input[i] != '\n' {
			input[i] = '*'
		}
	}
	return input
}

func toFinding(rule Rule, loc Location, content []byte) types.SecretFinding {
	startLine, endLine, code, matchLine := findLocation(loc.Start, loc.End, content)

	return types.SecretFinding{
		RuleID:    rule.ID,
		Category:  rule.Category,
		Severity:  lo.Ternary(rule.Severity == "", "UNKNOWN", rule.Severity),
		Title:     rule.Title,
		Match:     matchLine,
		StartLine: startLine,
		EndLine:   endLine,
		Code:      code,
	}
}

const (
	secretHighlightRadius = 2   // number of lines above + below each secret to include in code output
	maxLineLength         = 100 // all lines longer will be cut off
)

func findLocation(start, end int, content []byte) (int, int, types.Code, string) {
	startLineNum := bytes.Count(content[:start], lineSep)

	lineStart := bytes.LastIndex(content[:start], lineSep)
	if lineStart == -1 {
		lineStart = 0
	} else {
		lineStart++
	}

	lineEnd := bytes.Index(content[start:], lineSep)
	if lineEnd == -1 {
		lineEnd = len(content)
	} else {
		lineEnd += start
	}

	if lineEnd-lineStart > 100 {
		lineStart = lo.Ternary(start-lineStart-30 < 0, lineStart, start-30)
		lineEnd = lo.Ternary(end+20 > lineEnd, lineEnd, end+20)
	}
	matchLine := string(content[lineStart:lineEnd])
	endLineNum := startLineNum + bytes.Count(content[start:end], lineSep)

	var code types.Code

	lines := bytes.Split(content, lineSep)
	codeStart := lo.Ternary(startLineNum-secretHighlightRadius < 0, 0, startLineNum-secretHighlightRadius)
	codeEnd := lo.Ternary(endLineNum+secretHighlightRadius > len(lines), len(lines), endLineNum+secretHighlightRadius)

	rawLines := lines[codeStart:codeEnd]
	var foundFirst bool
	for i, rawLine := range rawLines {
		realLine := codeStart + i
		inCause := realLine >= startLineNum && realLine <= endLineNum

		var strRawLine string
		if len(rawLine) > maxLineLength {
			strRawLine = lo.Ternary(inCause, matchLine, string(rawLine[:maxLineLength]))
		} else {
			strRawLine = string(rawLine)
		}

		code.Lines = append(code.Lines, types.Line{
			Number:      codeStart + i + 1,
			Content:     strRawLine,
			IsCause:     inCause,
			Highlighted: strRawLine,
			FirstCause:  !foundFirst && inCause,
			LastCause:   false,
		})
		foundFirst = foundFirst || inCause
	}
	if len(code.Lines) > 0 {
		for i := len(code.Lines) - 1; i >= 0; i-- {
			if code.Lines[i].IsCause {
				code.Lines[i].LastCause = true
				break
			}
		}
	}

	return startLineNum + 1, endLineNum + 1, code, matchLine
}
