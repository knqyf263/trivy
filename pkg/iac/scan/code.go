package scan

import (
	"bufio"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Code struct {
	Lines []Line
}

type Line struct {
	Number      int    `json:"Number"`
	Content     string `json:"Content"`
	IsCause     bool   `json:"IsCause"`
	Annotation  string `json:"Annotation"`
	Truncated   bool   `json:"Truncated"`
	Highlighted string `json:"Highlighted,omitempty"`
	FirstCause  bool   `json:"FirstCause"`
	LastCause   bool   `json:"LastCause"`
}

func (c *Code) IsCauseMultiline() bool {
	var count int
	for _, line := range c.Lines {
		if line.IsCause {
			count++
			if count > 1 {
				return true
			}
		}
	}
	return false
}

const (
	darkTheme  = "solarized-dark256"
	lightTheme = "github"
)

type codeSettings struct {
	theme              string
	allowTruncation    bool
	maxLines           int
	includeHighlighted bool
}

var defaultCodeSettings = codeSettings{
	theme:              darkTheme,
	allowTruncation:    true,
	maxLines:           10,
	includeHighlighted: true,
}

type CodeOption func(*codeSettings)

func OptionCodeWithTheme(theme string) CodeOption {
	return func(s *codeSettings) {
		s.theme = theme
	}
}

func OptionCodeWithDarkTheme() CodeOption {
	return func(s *codeSettings) {
		s.theme = darkTheme
	}
}

func OptionCodeWithLightTheme() CodeOption {
	return func(s *codeSettings) {
		s.theme = lightTheme
	}
}

func OptionCodeWithTruncation(truncate bool) CodeOption {
	return func(s *codeSettings) {
		s.allowTruncation = truncate
	}
}

func OptionCodeWithMaxLines(lines int) CodeOption {
	return func(s *codeSettings) {
		s.maxLines = lines
	}
}

func OptionCodeWithHighlighted(include bool) CodeOption {
	return func(s *codeSettings) {
		s.includeHighlighted = include
	}
}

func validateRange(r iacTypes.Range) error {
	if r.GetStartLine() < 0 || r.GetStartLine() > r.GetEndLine() || r.GetEndLine() < 0 {
		return fmt.Errorf("invalid range: %s", r.String())
	}
	return nil
}

// nolint
func (r *Result) GetCode(opts ...CodeOption) (*Code, error) {

	settings := defaultCodeSettings
	for _, opt := range opts {
		opt(&settings)
	}

	srcFS := r.Range().GetFS()
	if srcFS == nil {
		return nil, fmt.Errorf("code unavailable: result was not mapped to a known filesystem")
	}

	innerRange := r.Range()
	outerRange := innerRange
	metadata := r.Metadata()
	for {
		if parent := metadata.Parent(); parent != nil &&
			parent.Range().GetFilename() == metadata.Range().GetFilename() &&
			parent.Range().GetStartLine() > 0 {
			outerRange = parent.Range()
			metadata = *parent
			continue
		}
		break
	}

	if err := validateRange(innerRange); err != nil {
		return nil, err
	}
	if err := validateRange(outerRange); err != nil {
		return nil, err
	}

	slashed := filepath.ToSlash(r.fsPath)
	slashed = strings.TrimPrefix(slashed, "/")

	hasAnnotation := r.Annotation() != ""

	numLines, err := countLines(srcFS, slashed)
	if err != nil {
		return nil, err
	}

	code := Code{
		Lines: nil,
	}

	if outerRange.GetEndLine()-1 >= numLines || innerRange.GetStartLine() == 0 {
		return nil, fmt.Errorf("invalid line number")
	}

	shrink := settings.allowTruncation && outerRange.LineCount() > (innerRange.LineCount()+10)
	if shrink {

		if outerRange.GetStartLine() < innerRange.GetStartLine() {
			code.Lines = append(
				code.Lines,
				Line{
					//Content:     rawLines[outerRange.GetStartLine()-1],
					//Highlighted: highlightedLines[outerRange.GetStartLine()-1],
					Number: outerRange.GetStartLine(),
				},
			)
			if outerRange.GetStartLine()+1 < innerRange.GetStartLine() {
				code.Lines = append(
					code.Lines,
					Line{
						Truncated: true,
						Number:    outerRange.GetStartLine() + 1,
					},
				)
			}
		}

		for lineNo := innerRange.GetStartLine(); lineNo <= innerRange.GetEndLine(); lineNo++ {

			if lineNo-1 >= numLines {
				break
			}

			line := Line{
				Number: lineNo,
				//Content:     strings.TrimSuffix(rawLines[lineNo-1], "\r"),
				//Highlighted: strings.TrimSuffix(highlightedLines[lineNo-1], "\r"),
				IsCause: true,
			}

			if hasAnnotation && lineNo == innerRange.GetStartLine() {
				line.Annotation = r.Annotation()
			}

			code.Lines = append(code.Lines, line)
		}

		if outerRange.GetEndLine() > innerRange.GetEndLine() {
			if outerRange.GetEndLine() > innerRange.GetEndLine()+1 {
				code.Lines = append(
					code.Lines,
					Line{
						Truncated: true,
						Number:    outerRange.GetEndLine() - 1,
					},
				)
			}
			code.Lines = append(
				code.Lines,
				Line{
					//Content:     rawLines[outerRange.GetEndLine()-1],
					//Highlighted: highlightedLines[outerRange.GetEndLine()-1],
					Number: outerRange.GetEndLine(),
				},
			)

		}

	} else {
		for lineNo := outerRange.GetStartLine(); lineNo <= outerRange.GetEndLine(); lineNo++ {

			line := Line{
				Number: lineNo,
				//Content:     strings.TrimSuffix(rawLines[lineNo-1], "\r"),
				//Highlighted: strings.TrimSuffix(highlightedLines[lineNo-1], "\r"),
				IsCause: lineNo >= innerRange.GetStartLine() && lineNo <= innerRange.GetEndLine(),
			}

			if hasAnnotation && lineNo == innerRange.GetStartLine() {
				line.Annotation = r.Annotation()
			}

			code.Lines = append(code.Lines, line)
		}
	}

	if settings.allowTruncation && len(code.Lines) > settings.maxLines && settings.maxLines > 0 {
		previouslyTruncated := settings.maxLines-1 > 0 && code.Lines[settings.maxLines-2].Truncated
		if settings.maxLines-1 > 0 && code.Lines[settings.maxLines-1].LastCause {
			code.Lines[settings.maxLines-2].LastCause = true
		}
		code.Lines[settings.maxLines-1] = Line{
			Truncated: true,
			Number:    code.Lines[settings.maxLines-1].Number,
		}
		if previouslyTruncated {
			code.Lines = code.Lines[:settings.maxLines-1]
		} else {
			code.Lines = code.Lines[:settings.maxLines]
		}
	}

	var first, last bool
	for i, line := range code.Lines {
		if line.IsCause && !first {
			code.Lines[i].FirstCause = true
			first = true
			continue
		}
		if first && !line.IsCause && i > 0 {
			code.Lines[i-1].LastCause = true
			last = true
			break
		}
	}
	if !last && len(code.Lines) > 0 {
		code.Lines[len(code.Lines)-1].LastCause = true
	}

	if err = fillContent(srcFS, slashed, innerRange.GetLocalFilename(), &code, settings); err != nil {
		return nil, err
	}

	return &code, nil
}

func countLines(srcFS fs.FS, name string) (int, error) {
	f, err := srcFS.Open(name)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lineCount int
	for scanner.Scan() {
		lineCount++
	}

	if err = scanner.Err(); err != nil {
		return 0, err
	}

	return lineCount, nil
}

func findFirstAndLastLine(code *Code) (int, int) {
	var firstLine, lastLine int
	for _, line := range code.Lines {
		if line.Truncated {
			continue
		}
		if firstLine == 0 {
			firstLine = line.Number
		}
		if lastLine < line.Number {
			lastLine = line.Number
		}
	}
	return firstLine, lastLine
}

// readLines reads the lines of the file in the range
func readLines(srcFS fs.FS, srcPath string, firstLine, lastLine int) ([]string, error) {
	f, err := srcFS.Open(srcPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var content []string
	lineNumber := 1 // Line number starts from 1
	bs := bufio.NewScanner(f)
	for bs.Scan() {
		if firstLine <= lineNumber && lineNumber <= lastLine {
			content = append(content, bs.Text())
		}
		lineNumber++
	}
	return content, nil
}

func highlightLines(srcFS fs.FS, localFileName string, lines []string, firstLine, lastLine int, settings codeSettings) []string {
	var highlightedLines []string
	if settings.includeHighlighted {
		highlightedLines = highlight(iacTypes.CreateFSKey(srcFS), localFileName, lines, firstLine, lastLine, settings.theme)
		if len(highlightedLines) < len(lines) {
			highlightedLines = lines
		}
	} else {
		highlightedLines = make([]string, len(lines))
	}
	return highlightedLines
}

func fillContent(srcFS fs.FS, srcPath, localFileName string, code *Code, settings codeSettings) error {
	firstLine, lastLine := findFirstAndLastLine(code)

	lines, err := readLines(srcFS, srcPath, firstLine, lastLine)
	if err != nil {
		return err
	}

	highlightedLines := highlightLines(srcFS, localFileName, lines, firstLine, lastLine, settings)

	for i, line := range code.Lines {
		if line.Truncated {
			continue
		}
		code.Lines[i].Content = lines[line.Number-firstLine]
		code.Lines[i].Highlighted = highlightedLines[line.Number-firstLine]
	}
	return nil
}
