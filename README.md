# Dependency Check Suppressions Cleaner

Caution: Always verify the result with a new dependency check.

Dependency Check Suppressions Cleaner (`supclean`) processes an XML report from OWASP Dependency-Check along with an associated suppression XML file.
It identifies suppression rules that apply to the vulnerabilities listed in the report, filters out irrelevant suppressions, and merges any duplicates.

Note: This is not an official OWASP project.

## Mode of operation

1. Parses an OWASP Dependency-Check XML report.
2. Parses an OWASP Dependency-Check suppression XML file.
3. Evaluates suppression rules against dependency vulnerabilities.
4. Removes non-applicable suppressions.
5. Merges duplicate suppressions.
6. Outputs consolidated suppressions as XML on STDOUT.

## Usage

### Command-line Parameters

- `-h`: Show help
- `-r string`: Path to the OWASP Dependency-Check ***r***eport XML file (default `dependency-check-report.xml`)
- `-s string`: Path to the OWASP Dependency-Check ***s***uppressions XML file (default `dependency-check-suppressions.xml`)
- `-ks`: Keep non-matching CVSS minimum ***s***core fil*ter from suppressions (often required for future checks)
- `-kw`: Keep non-matching C***W***E filters from suppressions (often required for future checks)
- `-u string`: Remove expired suppressions with '***u***ntil' attribute before this date: `now`, a RFC3339 date (`2020-01-01Z`), or `never` (default `now`)
- `-v`: Enable ***v***erbose mode
- `-vv`: Enable trace mode, implies verbose

### Example

An example of running the tool with debug mode enabled and specifying custom paths for input files:

```bash
./supclean -debug -report path/to/report.xml -suppress path/to/suppressions.xml > consolidated_suppressions.xml
```

### Output

The tool outputs consolidated suppressions in XML format. You can redirect it into a file via `>`. Logging is done to STDERR, so it will not end up in the suppressions file.

## Requirements

* Go

## Installation

To run the tool, you need to clone the repository and either start it directy with `go run supclean.go` or build the executable:

```bash
git clone https://github.com/dmatscheko/dependency-check-suppressions-cleaner.git
cd dependency-check-suppressions-cleaner
go build supclean.go
```

## Contributing

Contributions to this project are welcome! Please feel free to submit a pull request or open an issue for any bugs, feature requests, or questions.

## License

This project is licensed under the GPLv3 License. See the [LICENSE](LICENSE) file for more information.

## Author

This tool was created by David M.
