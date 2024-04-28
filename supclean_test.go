package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

// Mock XML Data
var (
	validReportXML = `
<analysis>
    <dependencies>
        <dependency>
            <fileName>lib1.jar</fileName>
            <filePath>/usr/local/lib/lib1.jar</filePath>
            <sha1>12345</sha1>
            <identifiers>
                <package>
                    <id>pkg:maven/group/artifact@version</id>
                </package>
            </identifiers>
            <vulnerabilities>
                <vulnerability>
                    <name>CVE-2020-1234</name>
                </vulnerability>
            </vulnerabilities>
        </dependency>
    </dependencies>
</analysis>`

	validSuppressionsXML = `
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">
    <suppress>
        <filePath regex="true">.*lib1\.jar</filePath>
        <cve>CVE-2020-1234</cve>
    </suppress>
</suppressions>`
)

// TestMain to mark the executable as in test mode.
func TestMain(m *testing.M) {
	IsTesting = true // Mark the current executable as in test mode
	os.Exit(m.Run())
}

// captureOutput captures both stdout and stderr outputs from the function f.
func captureOutput(f func()) (string, string) {
	// Backup the real stdout and stderr
	oldStdout, oldStderr := os.Stdout, os.Stderr

	// Create a pipe for stdout and stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	// Redirect stdout and stderr to the write-end of the pipe
	os.Stdout, os.Stderr = wOut, wErr

	f() // Execute function f

	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = oldStdout, oldStderr

	var bufOut, bufErr bytes.Buffer
	io.Copy(&bufOut, rOut)
	io.Copy(&bufErr, rErr)
	return bufOut.String(), bufErr.String()
}

// Tests
// ======

func TestToGAV(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Valid GAV", "pkg:maven/io.gitlab.arturbosch.detekt/detekt-core@1.0.0", "io.gitlab.arturbosch.detekt:detekt-core:1.0.0"},
		{"Invalid Format", "pkg:maven/io.gitlab.arturbosch.detekt/detekt-core", ""},
		{"Non-Maven", "pkg:npm/package@1.0.0", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identifier := Identifier{ID: test.input}
			result := identifier.ToGAV()
			if result != test.expected {
				t.Errorf("ToGAV() = %v, want %v", result, test.expected)
			}
		})
	}
}

func TestParseXML(t *testing.T) {
	report, err := ParseXMLData[Report]([]byte(validReportXML))
	if err != nil {
		t.Errorf("parseXML failed with error: %v", err)
	}
	if report.Dependencies[0].FileName != "lib1.jar" {
		t.Errorf("Expected FileName to be 'lib1.jar', got '%s'", report.Dependencies[0].FileName)
	}
	if report.Dependencies[0].Identifiers[0].ID != "pkg:maven/group/artifact@version" {
		t.Errorf("Expected ID to be 'pkg:maven/group/artifact@version', got '%s'", report.Dependencies[0].Identifiers[0].ID)
	}

	suppressions, err := ParseXMLData[Suppressions]([]byte(validSuppressionsXML))
	if err != nil {
		t.Errorf("parseXML failed with error: %v", err)
	}
	if suppressions.Suppresses[0].FilePath.Value != `.*lib1\.jar` {
		t.Errorf("Expected FilePath.Value to be '.*lib1\\.jar', got '%s'", suppressions.Suppresses[0].FilePath.Value)
	}
	if suppressions.Suppresses[0].CVE[0] != "CVE-2020-1234" {
		t.Errorf("Expected CVE to be 'CVE-2020-1234', got '%s'", suppressions.Suppresses[0].CVE[0])
	}
}

func TestParseCPE(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		want CPE
	}{
		{
			name: "Standard CPE",
			uri:  "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
			want: CPE{Part: "a", Vendor: "vendor", Product: "product", Version: "1.0"},
		},
		{
			name: "Incomplete CPE",
			uri:  "cpe:/a:vendor:product",
			want: CPE{Part: "a", Vendor: "vendor", Product: "product"},
		},
		{
			name: "CPE with wildcard characters",
			uri:  "cpe:/a:vendor:*:1.0:NA:-:DE",
			want: CPE{Part: "a", Vendor: "vendor", Version: "1.0", Language: "de"},
		},
		{
			name: "CPE with mixed case",
			uri:  "cpe:2.3:A:Gentoo:GLibC:2.5:R3:*:*:*:*:*:*",
			want: CPE{Part: "a", Vendor: "gentoo", Product: "glibc", Version: "2.5", Update: "r3"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseCPE(tc.uri); *got != tc.want {
				t.Errorf("ParseCPE(%q) = %+v, want %+v", tc.uri, *got, tc.want)
			}
		})
	}
}

func TestMatchesCPE(t *testing.T) {
	tests := []struct {
		name         string
		baseCPE      *CPE
		candidateCPE *CPE
		expected     bool
	}{
		{"All Match", &CPE{"a", "vendor", "product", "1.0", "update", "edition", "language"}, &CPE{"a", "vendor", "product", "1.0", "update", "edition", "language"}, true},
		{"Version Mismatch", &CPE{"a", "vendor", "product", "1.0", "update", "edition", "language"}, &CPE{"a", "vendor", "product", "2.0", "update", "edition", "language"}, false},
		{"One Blank", &CPE{"a", "", "product", "", "", "", ""}, &CPE{"a", "vendor", "product", "1.0", "update", "edition", "language"}, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := MatchesCPE(test.baseCPE, test.candidateCPE)
			if result != test.expected {
				t.Errorf("MatchesCPE() = %v, want %v", result, test.expected)
			}
		})
	}
}

func TestMatchCPEPart(t *testing.T) {
	tests := []struct {
		name      string
		base      string
		candidate string
		expected  bool
	}{
		{"Exact Match", "vendor", "vendor", true},
		{"No Match", "vendor", "different", false},
		{"Base Empty", "", "anything", true},
		{"Candidate Empty", "anything", "", false},
		{"Both Empty", "", "", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := matchCPEPart(test.base, test.candidate)
			if result != test.expected {
				t.Errorf("matchCPEPart(%s, %s) = %v, want %v", test.base, test.candidate, result, test.expected)
			}
		})
	}
}

// TODO:
func TestFilterSuppression(t *testing.T) {
	report, _ := ParseXMLData[Report]([]byte(validReportXML))
	suppressions, _ := ParseXMLData[Suppressions]([]byte(validSuppressionsXML))

	if !filterSuppression(&report, &suppressions.Suppresses[0]) {
		t.Errorf("Expected suppression to match, but it did not")
	}
}

func TestIsSuppressionExpired(t *testing.T) {
	untilDateFlag = new(string)

	suppression := Suppression{Until: "2024-01-01Z"}

	*untilDateFlag = "2024-12-31Z"
	if !isSuppressionExpired(&suppression) {
		t.Errorf("Suppression should be expired")
	}

	*untilDateFlag = "2024-01-02Z"
	if !isSuppressionExpired(&suppression) {
		t.Errorf("Suppression should be expired")
	}

	*untilDateFlag = "2024-01-01Z"
	if !isSuppressionExpired(&suppression) {
		t.Errorf("Suppression should be expired")
	}

	*untilDateFlag = "2023-01-01Z"
	if isSuppressionExpired(&suppression) {
		t.Errorf("Suppression should not be expired")
	}

	*untilDateFlag = "never"
	if isSuppressionExpired(&suppression) {
		t.Errorf("Suppression should not be expired")
	}

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("isSuppressionExpired did not panic")
			}
		}()

		*untilDateFlag = "1980-invalid-date"
		captureOutput(func() {
			isSuppressionExpired(&suppression)
		})
	}()

	suppression.Until = "2025-invalid-date"

	*untilDateFlag = "1980-01-01Z"
	if !isSuppressionExpired(&suppression) {
		t.Errorf("Suppression should be expired")
	}

	suppression.Until = ""

	*untilDateFlag = "1980-01-01Z"
	if isSuppressionExpired(&suppression) {
		t.Errorf("Suppression should not be expired")
	}

	*untilDateFlag = "2025-12-12Z"
	if isSuppressionExpired(&suppression) {
		t.Errorf("Suppression should not be expired")
	}
}

func TestIsPackageMatching(t *testing.T) {
	tests := []struct {
		name        string
		dependency  Dependency
		suppression Suppression
		want        bool
	}{
		{
			name:       "Match by filePath regex",
			dependency: Dependency{FilePath: "src/lib/test.jar"},
			suppression: Suppression{
				PackageIdentifiers: PackageIdentifiers{
					FilePath: &RegexStringType{Value: ".*test\\.jar", Regex: true},
				},
			},
			want: true,
		},
		{
			name:       "Match by SHA1",
			dependency: Dependency{SHA1: "123456"},
			suppression: Suppression{
				PackageIdentifiers: PackageIdentifiers{
					SHA1: stringPtr("123456"),
				},
			},
			want: true,
		},
		{
			name:       "No match",
			dependency: Dependency{FilePath: "src/lib/prod.jar"},
			suppression: Suppression{
				PackageIdentifiers: PackageIdentifiers{
					FilePath: &RegexStringType{Value: ".*test\\.jar", Regex: true},
				},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPackageMatching(&tc.dependency, &tc.suppression); got != tc.want {
				t.Errorf("isPackageMatching() = %v, want %v", got, tc.want)
			}
		})
	}
}

func stringPtr(s string) *string {
	return &s
}

// TODO: Better comparison needed
func TestFullProcessing(t *testing.T) {
	*reportXMLFlag = "test/dependency-check-report.xml"
	*suppressionsXMLFlag = "test/dependency-check-suppressions.xml"
	*verboseFlag = true
	*untilDateFlag = "2024-05-01Z"
	outputStdout, outputStderr := captureOutput(func() {
		main()
	})

	if !strings.Contains(outputStderr, "======== Dependencies without known vulnerabilites:") {
		t.Errorf("Verbose output was expected, but not found in the output")
	}

	// ioutil.WriteFile("test/result.xml", []byte(outputStdout), 0644)

	expected, err := ioutil.ReadFile("test/result.xml")
	if err != nil {
		t.Errorf("Could not read result.xml")
	}
	expectedStr := string(expected)

	if expectedStr != outputStdout {
		t.Errorf("Output XML does not match expectation in result.xml")
	}

}
