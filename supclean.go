/*
This tool processes XML reports from OWASP Dependency-Check along with associated suppression rules.
It evaluates which suppression rules are applicable to the dependencies listed in the XML report
and outputs only those suppressions that are relevant. It also merges duplicate suppressions.

(c) 2024 David M.
GPLv3

// In a suppression, select files or packages via none or one of the following package identifiers (none selects all packages):
// 		<filePath regex="true">.*\btest\.jar</filePath>
// 		<sha1>384FAA82E193D4E4B0546059CA09572654BC3970</sha1>
// 		<gav regex="true">^io\.gitlab\.arturbosch\.detekt:detekt-.+:.*$</gav>		(Maven Group : Artifact : Version)
// 		<packageUrl regex="true">^pkg:maven/io\.gitlab\.arturbosch\.detekt/detekt\-core@.*$</packageUrl>
//                     defined as:
// 		<xs:choice minOccurs="0" maxOccurs="1">
// 		<xs:element name="filePath" type="dc:regexStringType"/>
// 		<xs:element name="sha1" type="dc:sha1Type"/>
// 		<xs:element name="gav" type="dc:regexStringType"/>
// 		<xs:element name="packageUrl" type="dc:regexStringType"/>
// 		</xs:choice>
//
// And/or match for (possible multiple) vulnerabilities via one or many of the following vulnerability identifiers:
// 		<cpe>cpe:/a:csv:csv:1.0</cpe>
// 		<cve>CVE-2013-1337</cve>
// 		<vulnerabilityName>CVE-2017-7656</vulnerabilityName>
// 		<cwe>400</cwe>
// 		<cvssBelow>7</cvssBelow>
//                     defined as:
// 		<xs:choice minOccurs="1" maxOccurs="unbounded">
// 		<xs:element name="cpe" type="dc:regexStringType"/>
// 		<xs:element name="cve" type="dc:cveType"/>
// 		<xs:element name="vulnerabilityName" type="dc:regexStringType"/>
// 		<xs:element name="cwe" type="xs:positiveInteger"/>
// 		<xs:element name="cvssBelow" type="dc:cvssScoreType"/>
// 		</xs:choice>
//
// A vulnerability identifier can be used without a package identifier.
*/

// TODO: GAV and packageUrl suppressions can and probably should be unified

package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"time"
)

// Define command line parameters
var (
	verboseFlag         = flag.Bool("v", false, "Enable [v]erbose mode")
	traceFlag           = flag.Bool("vv", false, "Enable trace mode, implies verbose")
	reportXMLFlag       = flag.String("r", "dependency-check-report.xml", "Path to the OWASP Dependency-Check [r]eport XML file")
	suppressionsXMLFlag = flag.String("s", "dependency-check-suppressions.xml", "Path to the OWASP Dependency-Check [s]uppressions XML file")
	cvssFlag            = flag.Bool("ks", false, "Keep non-matching CVSS minimum [s]core filters from suppressions (often required for future checks)")
	cweFlag             = flag.Bool("kw", false, "Keep non-matching CWE filters from suppressions (often required for future checks)")
	untilDateFlag       = flag.String("u", "now", "Remove expired suppressions with '[u]ntil' attribute before this date: \"now\", a RFC3339 date (\"2020-01-01Z\"), or \"never\"")
)

// Bool for test handling
var IsTesting = false

// Log handling
// ============

// Trace logs a debug message if the trace flag is set.
func Trace(format string, args ...interface{}) {
	if *traceFlag {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

// Verbose logs an informational message if the verbose flag is set.
func Verbose(format string, args ...interface{}) {
	if *verboseFlag {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

// Warn logs a warning message.
func Warn(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
}

// XML handling
// ============

// Structs for Report XML processing

// Report represents the top-level structure of an XML report with dependencies.
type Report struct {
	XMLName      xml.Name     `xml:"analysis"`
	Dependencies []Dependency `xml:"dependencies>dependency"`
}

// Dependency represents a software dependency with potential vulnerabilities.
type Dependency struct {
	FileName        string          `xml:"fileName"`
	FilePath        string          `xml:"filePath"`
	SHA1            string          `xml:"sha1"`
	Identifiers     []Identifier    `xml:"identifiers>package"`
	Vulnerabilities Vulnerabilities `xml:"vulnerabilities"`
	suppressed      bool            // Tracks whether the dependency has been suppressed
}

// HasVulnerabilities checks if there are any vulnerabilities associated with the dependency.
func (d *Dependency) HasVulnerabilities() bool {
	return len(d.Vulnerabilities.Open) > 0 || len(d.Vulnerabilities.Suppressed) > 0
}

// Identifier represents a unique identifier of a package.
type Identifier struct {
	ID  string `xml:"id"`
	gav string // Holds the ID as GAV so that it has to be converted only once
}

// ToGAV takes a package ID in the format "pkg:maven/group/artifact@version"
// and converts it to the Maven GAV format "group:artifact:version".
func (identifier *Identifier) ToGAV() string {
	if identifier.gav != "" {
		return identifier.gav
	}
	if !strings.HasPrefix(identifier.ID, "pkg:maven/") {
		return ""
	}

	trimmed := strings.TrimPrefix(identifier.ID, "pkg:maven/")
	parts := strings.Split(trimmed, "@")
	if len(parts) != 2 {
		return ""
	}
	identifier.gav = strings.Replace(parts[0], "/", ":", 1) + ":" + parts[1]

	return identifier.gav
}

// Vulnerabilities contains lists of open and suppressed vulnerabilities.
type Vulnerabilities struct {
	Open       []Vulnerability `xml:"vulnerability"`
	Suppressed []Vulnerability `xml:"suppressedVulnerability"`
}

// Vulnerability represents a single vulnerability entry.
type Vulnerability struct {
	Source             string   `xml:"source,attr"`
	Name               string   `xml:"name"`
	CVSSv2Score        *float64 `xml:"cvssV2>score,omitempty"`
	CVSSv3BaseScore    *float64 `xml:"cvssV3>baseScore,omitempty"`
	CWEs               []string `xml:"cwes>cwe,omitempty"`
	VulnerableSoftware []string `xml:"vulnerableSoftware>software"`
}

// Structs for Suppressions XML processing

// Suppressions represents the top-level structure of an XML with vulnerability suppressions.
type Suppressions struct {
	XMLName    xml.Name      `xml:"https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd suppressions"`
	Suppresses []Suppression `xml:"suppress"`
}

// Suppression represents a single suppression rule for a vulnerability.
type Suppression struct {
	Notes CDATA `xml:"notes,omitempty"`
	PackageIdentifiers
	VulnerabilityIdentifiers
	Base  bool   `xml:"base,attr,omitempty"`
	Until string `xml:"until,attr,omitempty"`
}

// PackageIdentifiers identifies one or multiple dependencies. Only a single identifier can be used.
type PackageIdentifiers struct {
	FilePath   *RegexStringType `xml:"filePath,omitempty"`
	SHA1       *string          `xml:"sha1,omitempty"`
	GAV        *RegexStringType `xml:"gav,omitempty"`
	PackageUrl *RegexStringType `xml:"packageUrl,omitempty"`
}

// VulnerabilityIdentifiers identifies one or multiple dependencies. Multiple identifiers can be used.
type VulnerabilityIdentifiers struct {
	CPE               []RegexStringType `xml:"cpe,omitempty"`
	CVE               []string          `xml:"cve,omitempty"`
	VulnerabilityName []RegexStringType `xml:"vulnerabilityName,omitempty"`
	CWE               []int             `xml:"cwe,omitempty"`
	CVSSBelow         []float64         `xml:"cvssBelow,omitempty"`
}

// Append merges another VulnerabilityIdentifiers instance into this one by appending its elements to the corresponding slices.
func (vi *VulnerabilityIdentifiers) Append(more *VulnerabilityIdentifiers) {
	vi.CPE = append(vi.CPE, more.CPE...)
	vi.CVE = append(vi.CVE, more.CVE...)
	vi.VulnerabilityName = append(vi.VulnerabilityName, more.VulnerabilityName...)
	vi.CWE = append(vi.CWE, more.CWE...)
	vi.CVSSBelow = append(vi.CVSSBelow, more.CVSSBelow...)
}

// HasEntries checks if any of the identifier slices within the struct have entries.
func (vi *VulnerabilityIdentifiers) HasEntries() bool {
	return len(vi.CPE) > 0 || len(vi.CVE) > 0 || len(vi.VulnerabilityName) > 0 || len(vi.CWE) > 0 || len(vi.CVSSBelow) > 0
}

// RegexStringType represents a regex-enabled string type.
type RegexStringType struct {
	Value         string `xml:",chardata"`
	Regex         bool   `xml:"regex,attr,omitempty"`
	CaseSensitive bool   `xml:"caseSensitive,attr,omitempty"`
}

// CDATA represents a string wrapped in CDATA XML tag.
type CDATA string

// MarshalXML encodes the CDATA value.
func (c CDATA) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	// Wrap the value in a CDATA section
	return e.EncodeElement(struct {
		string `xml:",cdata"`
	}{string(c)}, start)
}

// ParseXML handles opening, reading, and parsing an XML file.
func ParseXML[T any](filePath string) (T, error) {
	var result T
	xmlFile, err := os.Open(filePath)
	if err != nil {
		return result, fmt.Errorf("error opening XML file: %w", err)
	}
	defer xmlFile.Close()

	xmlData, err := ioutil.ReadAll(xmlFile)
	if err != nil {
		return result, fmt.Errorf("error reading XML file: %w", err)
	}

	return ParseXMLData[T](xmlData)
}

// ParseXMLData takes byte slice of XML data and parses it into the provided type T.
func ParseXMLData[T any](data []byte) (T, error) {
	var result T
	if err := xml.Unmarshal(data, &result); err != nil {
		return result, fmt.Errorf("error parsing XML data: %w", err)
	}
	return result, nil
}

// CPE handling
// ============

// CPE struct represents components of a Common Platform Enumeration (CPE) URI.
type CPE struct {
	Part, Vendor, Product, Version, Update, Edition, Language string
}

// regexCPEPrefix identifies the standard prefix in a CPE URI.
var regexCPEPrefix = regexp.MustCompile(`^cpe:[0-9.]*[:/]`)

// ParseCPE parses a CPE URI into a CPE struct.
func ParseCPE(uri string) *CPE {
	uri = strings.ToLower(uri)
	uri = trimCPEPrefix(uri)
	parts := strings.Split(uri, ":")

	return &CPE{
		Part:     getCPEPart(parts, 0),
		Vendor:   getCPEPart(parts, 1),
		Product:  getCPEPart(parts, 2),
		Version:  getCPEPart(parts, 3),
		Update:   getCPEPart(parts, 4),
		Edition:  getCPEPart(parts, 5),
		Language: getCPEPart(parts, 6),
	}
}

// trimCPEPrefix removes the CPE prefix from the URI.
func trimCPEPrefix(uri string) string {
	if strings.HasPrefix(uri, "cpe:/") {
		return uri[5:]
	} else if strings.HasPrefix(uri, "cpe:2.3:") {
		return uri[8:]
	} else if strings.HasPrefix(uri, "cpe:") {
		return regexCPEPrefix.ReplaceAllString(uri, "")
	}
	// Not a valid CPE URI
	return "NOCPE:NOCPE:NOCPE:NOCPE:NOCPE:NOCPE:NOCPE" // Can never match since all other CPE URIs are lowercase
}

// getCPEPart safely extracts a value from a slice by index, returning an empty string if the index is out of bounds.
func getCPEPart(slice []string, index int) string {
	if index >= len(slice) {
		return ""
	}
	part := slice[index]
	if part == "*" || part == "-" || part == "any" || part == "na" {
		return ""
	}
	return part
}

// MatchesCPE checks if two CPE structures are equivalent in all their parts.
func MatchesCPE(c1, c2 *CPE) bool {
	return matchCPEPart(c1.Part, c2.Part) &&
		matchCPEPart(c1.Vendor, c2.Vendor) &&
		matchCPEPart(c1.Product, c2.Product) &&
		matchCPEPart(c1.Version, c2.Version) &&
		matchCPEPart(c1.Update, c2.Update) &&
		matchCPEPart(c1.Edition, c2.Edition) &&
		matchCPEPart(c1.Language, c2.Language)
}

// matchCPEPart compares two CPE URI components, allowing matches based on CPE specification rules.
func matchCPEPart(base, candidate string) bool {
	// A candidate must match the base or be more specific (non-blank when base is blank)
	return base == candidate || base == ""
}

// Suppression handling
// ====================

// filterSuppression iterates through all dependencies, and returns true if any matches the given suppression (FilePath, SHA1, GAV, PackageUrl).
// Side effects:
//    * Modifies suppression, where it filters out CPE, CVE, VulnerabilityName, CWE, end CVSSBelow that are not used anymore.
//    * Marks dependencies where a suppression matches as suppressed.
func filterSuppression(report *Report, suppression *Suppression) bool {
	if isSuppressionExpired(suppression) {
		return false
	}

	var anyMatch = false
	var allFilteredVIs = VulnerabilityIdentifiers{}

	for i := range report.Dependencies {
		dependency := &report.Dependencies[i]

		// If the current dependency matches by package identifier, check if the suppressions vulnerabilities also match
		if isPackageMatching(dependency, suppression) {
			filteredVIs := filterVulnerabilities(dependency, suppression)

			// Only proceed if secondary checks also pass
			if filteredVIs.HasEntries() {
				anyMatch = true
				allFilteredVIs.Append(filteredVIs)
				// Mark dependency as suppressed
				dependency.suppressed = true
			} else {
				Trace("  Dependency is no real match: %s\n", dependency.FileName)
			}
		}
	}

	// Modify the suppressions vulnerability identifier
	suppression.VulnerabilityIdentifiers = allFilteredVIs

	if !anyMatch {
		Trace("No matching dependencies found\n")
	}
	return anyMatch
}

// isSuppressionExpired checks if the 'until' date of a suppression is still valid.
func isSuppressionExpired(suppression *Suppression) bool {
	if *untilDateFlag == "never" || suppression.Until == "" {
		return false
	}

	const layout = "2006-01-02Z07" // See time.RFC3339

	var date time.Time
	var err error
	if *untilDateFlag == "now" {
		date = time.Now()
	} else {
		date, err = time.Parse(layout, *untilDateFlag)
		if err != nil {
			panic(fmt.Errorf("invalid date format on cmd line for 'until': %v", err))
		}
	}
	expirationDate, err := time.Parse(layout, suppression.Until)
	if err != nil {
		Warn("warning: invalid date format in 'until' attribute: %v\n", err)
		return true
	}

	expired := !date.Before(expirationDate) // The dependency-suppression.1.2.xsd states: "On and after the 'until' date the suppression will no longer be active"
	return expired
}

// isPackageMatching checks if a dependency matches the package identifier of the suppression.
func isPackageMatching(dependency *Dependency, suppression *Suppression) bool {
	switch {
	case suppression.FilePath != nil && suppression.FilePath.Value != "":
		if isRegexStringMatching(dependency.FilePath, suppression.FilePath) {
			Trace("Matching FilePath: %s => %s (%s)\n", suppression.FilePath.Value, dependency.FilePath, dependency.FileName)
			return true
		}
	case suppression.SHA1 != nil && *suppression.SHA1 != "":
		if dependency.SHA1 == *suppression.SHA1 {
			Trace("Matching SHA1: %s (%s)\n", dependency.SHA1, dependency.FileName)
			return true
		}
	case suppression.GAV != nil && suppression.GAV.Value != "":
		for _, identifier := range dependency.Identifiers {
			if isRegexStringMatching(identifier.ToGAV(), suppression.GAV) {
				Trace("Matching GAV: %s => %s (%s)\n", suppression.GAV.Value, identifier.ToGAV(), dependency.FileName)
				return true
			}
		}
	case suppression.PackageUrl != nil && suppression.PackageUrl.Value != "":
		for _, identifier := range dependency.Identifiers {
			if isRegexStringMatching(identifier.ID, suppression.PackageUrl) {
				Trace("Matching PackageUrl: %s => %s (%s)\n", suppression.PackageUrl.Value, identifier.ID, dependency.FileName)
				return true
			}
		}
	default:
		// Without a package identifier, all packages / dependencies match
		return true
	}

	return false
}

// isRegexStringMatching checks if a text matches the criteria, considering regex and case sensitivity.
func isRegexStringMatching(text string, criteria *RegexStringType) bool {
	if criteria == nil {
		return false
	}

	if criteria.Regex {
		re, err := regexp.Compile(makeRegexPattern(criteria.Value, criteria.CaseSensitive))
		if err != nil {
			Warn("warning: regex error: %v\n", err)
			return false
		}
		return re.MatchString(text)
	}

	if criteria.CaseSensitive {
		return text == criteria.Value
	}
	return strings.EqualFold(text, criteria.Value)
}

// makeRegexPattern adjusts the regex pattern based on case sensitivity.
func makeRegexPattern(pattern string, caseSensitive bool) string {
	if caseSensitive {
		return pattern
	}
	return "(?i)" + pattern
}

// filterVulnerabilities returns all vulnerability identifiers that match a vulnerability of the dependency.
// It checks if an
//   CPE (Common Platform Enumeration identifiers) -> one of vulnerableSoftware.[]software
//   CVE -> one of []suppressedVulnerability.name
//   VulnerabilityName -> one of []suppressedVulnerability.name (potential regex)
//   CWE one of []suppressedVulnerability.cwes.[]cwe
//   CVSSBelow in []suppressedVulnerability.cvssV2.score or []suppressedVulnerability.cvssV3.baseScore
// matches.
func filterVulnerabilities(dependency *Dependency, suppression *Suppression) *VulnerabilityIdentifiers {
	var allFilteredVIs = VulnerabilityIdentifiers{}

	for i := range dependency.Vulnerabilities.Open {
		filteredVIs := filterVulnerability(&dependency.Vulnerabilities.Open[i], suppression)

		// If a more narrow identifier matches, remove the generic ones (if not specifed otherwise per cmd line flag)
		if len(filteredVIs.CPE) > 0 || len(filteredVIs.CVE) > 0 || len(filteredVIs.VulnerabilityName) > 0 {
			if !*cweFlag {
				filteredVIs.CWE = nil
			}
			if !*cvssFlag {
				filteredVIs.CVSSBelow = nil
			}
		}

		allFilteredVIs.Append(filteredVIs)
	}
	for i := range dependency.Vulnerabilities.Suppressed {
		filteredVIs := filterVulnerability(&dependency.Vulnerabilities.Suppressed[i], suppression)

		// If a more narrow identifier matches, remove the generic ones (if not specifed otherwise per cmd line flag)
		if len(filteredVIs.CPE) > 0 || len(filteredVIs.CVE) > 0 || len(filteredVIs.VulnerabilityName) > 0 {
			if !*cweFlag {
				filteredVIs.CWE = nil
			}
			if !*cvssFlag {
				filteredVIs.CVSSBelow = nil
			}
		}

		allFilteredVIs.Append(filteredVIs)
	}

	return &allFilteredVIs
}

// filterVulnerability returns the vulnerability identifier that first matches the vulnerability (all others are not needed, even if they would match).
// Exceptions are CWE and CVSS score identifiers, which are kept in addition to the more specific ones.
func filterVulnerability(vuln *Vulnerability, suppression *Suppression) *VulnerabilityIdentifiers {
	var filteredVIs = VulnerabilityIdentifiers{}

	// CWE and CVSS score identifiers need to be kept in addition to the more specific ones, so they must be processed first

	if *cweFlag {
		// Just pass the CWEs along
		filteredVIs.CWE = suppression.CWE
	} else {
		// Filter CWE entries
		for _, cwe := range suppression.CWE {
			// Convert CWE from int to string and compare
			cweStr := fmt.Sprintf("CWE-%d", cwe)
			for _, c := range vuln.CWEs {
				if c == cweStr {
					filteredVIs.CWE = append(filteredVIs.CWE, cwe)
					Trace("   * CWE matched: %s\n", c)
					break
				}
			}
		}
	}

	if *cvssFlag {
		// Just pass the CVSS scores along
		filteredVIs.CVSSBelow = suppression.CVSSBelow
	} else {
		// Filter CVSS scores
		for _, cvssBelow := range suppression.CVSSBelow {
			if (vuln.CVSSv2Score != nil && *vuln.CVSSv2Score < cvssBelow) || (vuln.CVSSv3BaseScore != nil && *vuln.CVSSv3BaseScore < cvssBelow) {
				filteredVIs.CVSSBelow = append(filteredVIs.CVSSBelow, cvssBelow)
				Trace("   * CVSSBelow matched: %f\n", cvssBelow)
			}
		}
	}

	// Only one of all other vulnerability identifiers has to match

	// Filter CPE entries
	for _, suppressionCPE := range suppression.CPE {
		for _, software := range vuln.VulnerableSoftware {
			baseCPE := ParseCPE(suppressionCPE.Value)
			candidateCPE := ParseCPE(software)
			if MatchesCPE(baseCPE, candidateCPE) {
				filteredVIs.CPE = append(filteredVIs.CPE, suppressionCPE)
				Trace("   * CPE matched: %s\n", software)
				return &filteredVIs
			}
		}
	}

	// Filter CVE entries
	for _, cve := range suppression.CVE {
		if vuln.Name == cve {
			filteredVIs.CVE = append(filteredVIs.CVE, cve)
			Trace("   * CVE matched: %s\n", vuln.Name)
			return &filteredVIs
		}
	}

	// Filter VulnerabilityName entries
	for _, vulnName := range suppression.VulnerabilityName {
		if isRegexStringMatching(vuln.Name, &vulnName) {
			filteredVIs.VulnerabilityName = append(filteredVIs.VulnerabilityName, vulnName)
			Trace("   * VulnName matched: %s\n", vuln.Name)
			return &filteredVIs
		}
	}

	return &filteredVIs
}

// unifySuppressions merges suppressions based on their unique criteria.
func unifySuppressions(suppresses []Suppression) []Suppression {
	merged := []Suppression{}

	// Use a map to identify duplicates based on non-list fields
	seen := make(map[string]int)
	for _, sup := range suppresses {
		key := suppressionKey(&sup)

		if idx, exists := seen[key]; exists {
			// Merge the notes
			merged[idx].Notes = merged[idx].Notes + "\n--------\n" + sup.Notes
			// Merge the vulnerability identifier fields
			merged[idx].VulnerabilityIdentifiers.Append(&sup.VulnerabilityIdentifiers)
		} else {
			seen[key] = len(merged)
			merged = append(merged, sup)
		}
	}

	// Remove duplicates from all vulnerability identifiers
	for i := range merged {
		merged[i].CPE = removeDuplicatesRegex(merged[i].CPE)
		merged[i].CVE = removeDuplicatesString(merged[i].CVE)
		merged[i].VulnerabilityName = removeDuplicatesRegex(merged[i].VulnerabilityName)
		merged[i].CWE = removeDuplicatesInt(merged[i].CWE)
		merged[i].CVSSBelow = collapseToMinimum(merged[i].CVSSBelow)
	}

	return merged
}

// suppressionKey generates a unique key for a suppression to identify duplicates.
func suppressionKey(sup *Suppression) string {
	sha1Part := ""
	if sup.SHA1 != nil {
		sha1Part = *sup.SHA1
	}
	// Include all unique fields to form a key
	return fmt.Sprintf("<FilePath>%s|<SHA1>%s|<GAV>%s|<PackageUrl>%s|<Base>%t|<Until>%s",
		toKeyPart(sup.FilePath), sha1Part, toKeyPart(sup.GAV), toKeyPart(sup.PackageUrl), sup.Base, sup.Until)
}

// toKeyPart generates one part for the unique suppression key.
func toKeyPart(rst *RegexStringType) string {
	if rst == nil {
		return ""
	}
	return fmt.Sprintf("%s|%t|%t", rst.Value, rst.CaseSensitive, rst.Regex)
}

// removeDuplicatesString removes duplicates from a slice of strings.
func removeDuplicatesString(strings []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range strings {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// removeDuplicatesInt removes duplicates from a slice of integers.
func removeDuplicatesInt(ints []int) []int {
	keys := make(map[int]bool)
	list := []int{}
	for _, entry := range ints {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// removeDuplicatesRegex removes duplicates from a slice of RegexStringType objects.
func removeDuplicatesRegex(regexes []RegexStringType) []RegexStringType {
	keys := make(map[string]bool)
	list := []RegexStringType{}
	for _, entry := range regexes {
		if _, value := keys[entry.Value]; !value {
			keys[entry.Value] = true
			list = append(list, entry)
		}
	}
	return list
}

// collapseToMinimum finds the minimum value in a slice of floats and returns a slice containing only that value.
func collapseToMinimum(floats []float64) []float64 {
	if len(floats) == 0 {
		return floats
	}
	min := floats[0]
	for _, f := range floats {
		if f < min {
			min = f
		}
	}
	return []float64{min}
}

// run does what main() normally does and returns a status code.
func run() int {
	// Parse command line parameters
	flag.Parse()
	if flag.NArg() > 0 {
		Warn("unknown command line parameter: %s\n", flag.Arg(0))
		flag.Usage()
		return 2
	}
	*verboseFlag = *verboseFlag || *traceFlag

	// Parse report XML
	report, err := ParseXML[Report](*reportXMLFlag)
	if err != nil {
		Warn("failed to parse report XML: %v\n", err)
		return 1
	}

	// Parse suppressions XML
	suppressions, err := ParseXML[Suppressions](*suppressionsXMLFlag)
	if err != nil {
		Warn("failed to parse suppressions XML: %v\n", err)
		return 1
	}

	// Remove dependencies without known vulnerabilites
	Verbose("======== Dependencies without known vulnerabilites:\n")
	var remainingDependencies []Dependency
	for _, dependency := range report.Dependencies {
		if dependency.HasVulnerabilities() {
			remainingDependencies = append(remainingDependencies, dependency)
		} else {
			Verbose("  %s\n", dependency.FileName)
		}
	}
	report.Dependencies = remainingDependencies

	// Remove suppressions without dependencies
	Trace("\n======== Work trace:\n")
	var matchingSuppressions []Suppression
	for _, suppression := range suppressions.Suppresses {
		anyMatch := filterSuppression(&report, &suppression)
		if anyMatch {
			matchingSuppressions = append(matchingSuppressions, suppression)
		}
	}

	// Merge duplicates and collapse minimum values
	matchingSuppressions = unifySuppressions(matchingSuppressions)

	// Set the suppressions to only the matching and merged ones
	suppressions.Suppresses = matchingSuppressions

	if *verboseFlag {
		// Output suppressed and not suppressed vulnerable dependencies
		fmt.Fprintln(os.Stderr, "\n======== Matching vulnerable dependencies:")
		for _, dependency := range report.Dependencies {
			if dependency.suppressed {
				fmt.Fprintln(os.Stderr, "  ", dependency.FileName)
			}
		}
		fmt.Fprintln(os.Stderr, "\n======== Remaining vulnerable dependencies:")
		for _, dependency := range report.Dependencies {
			if !dependency.suppressed {
				fmt.Fprintln(os.Stderr, "  ", dependency.FileName)
			}
		}

		// Print title for the suppressions XML
		fmt.Fprintln(os.Stderr, "\n======== XML of Suppressions:")
	}

	// Marshal the Suppressions struct to XML
	xmlOutput, err := xml.MarshalIndent(suppressions, "", "	")
	if err != nil {
		Warn("unable to marshal suppressions into XML format: %v\n", err)
	}

	// Print the suppressions XML
	fmt.Println(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" + string(xmlOutput))

	return 0
}

// main only catches panics and returns the status code to the OS (if the current binary is not in test mode).
func main() {
	code := run()

	err := recover()
	if err != nil {
		Warn("%v\n", err)
		if !IsTesting {
			os.Exit(1)
		}
	}

	if !IsTesting {
		os.Exit(code)
	}
}
