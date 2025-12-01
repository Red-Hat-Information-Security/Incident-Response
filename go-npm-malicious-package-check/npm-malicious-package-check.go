// npm_malicious_package_check.go
//
// Usage:
//   go run npm_malicious_package_check.go
//   go run npm_malicious_package_check.go /path/to/scan
//
// Description:
//   Walk the filesystem starting at / (or a given path) and look for
//   malicious NPM packages and host IoCs, similar to the Python version.
//
// Rewritten from the python version with the help of AI.

package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	OSSFMalPackageDBURL = "https://raw.githubusercontent.com/Red-Hat-Information-Security/Incident-Response/refs/heads/main/data/ossf-malicious-npm-packages.txt"
	RHISMalPackageDBURL = "https://raw.githubusercontent.com/Red-Hat-Information-Security/Incident-Response/refs/heads/main/data/rhis-malicious-npm-packages.csv"
	RHISMalPackageIOCDB = "https://raw.githubusercontent.com/Red-Hat-Information-Security/Incident-Response/refs/heads/main/data/rhis-malicious-npm-package-host-iocs.csv"
)

const disclaimer = `
===============================================================================
DISCLAIMER
-------------------------------------------------------------------------------
This program can miss things. It's meant to be a basic check against packages
in the following sources with specific versions listed:

- https://github.com/ossf/malicious-packages
- https://github.com/red-hat-information-security/incident-response
===============================================================================
`

type packageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type finding struct {
	Path    string
	Finding string
	Context string
}

type ioc struct {
	Type        string
	Pattern     string
	Regex       *regexp.Regexp
	Description string
	Campaign    string
}

func main() {
	fmt.Println(disclaimer)
	var scanRoot string

	if len(os.Args) == 2 {
		// User provided a path → normalize it
		if abs, err := filepath.Abs(os.Args[1]); err == nil {
			scanRoot = abs
		} else {
			scanRoot = os.Args[1]
		}
	} else {
		// No args → choose OS-specific default
		if runtime.GOOS == "windows" {
			scanRoot = `C:\`
		} else {
			scanRoot = "/"
		}
	}

	findings, err := scanForIOCs(scanRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	if len(findings) == 0 {
		// [PHEW] No malicious packages found
		fmt.Println("\033[1m[\033[92mPHEW\033[0m\033[1m] No malicious packages found\033[0m")
		return
	}

	fmt.Println("\033[1m[\033[91mWARNING\033[0m\033[1m] Malicious Package IoC(s) Found:\033[0m\n")
	for _, f := range findings {
		fmt.Println("- Finding:", f.Finding)
		fmt.Println("  Context:", f.Context)
		fmt.Println("  Location:", f.Path)
		fmt.Println()
	}

	fmt.Println("\033[1m[\033[93mIMPORTANT\033[0m\033[1m] Please include the following in your ticket to InfoSec:\033[0m\n")
	fmt.Println("- \033[1mALL OF THE SCRIPT OUTPUT ABOVE\033[0m")
	fmt.Println("- Username:", currentUsername())
	fmt.Println("- Hostname:", currentHostname())
	fmt.Println("- Timestamp:", time.Now().Unix())
}

func scanForIOCs(scanRoot string) ([]finding, error) {
	maliciousPackages, err := loadMaliciousNpmPackages()
	if err != nil {
		return nil, err
	}

	hostIOCs, err := loadMaliciousPackageHostIOCs()
	if err != nil {
		return nil, err
	}

	var dirIOCs []ioc
	var fileIOCs []ioc
	for _, i := range hostIOCs {
		switch strings.ToLower(i.Type) {
		case "directory":
			dirIOCs = append(dirIOCs, i)
		case "file":
			fileIOCs = append(fileIOCs, i)
		}
	}

	fmt.Println("Scanning for Indicators of Compromise (IoCs)...\n")
	var findings []finding

	err = filepath.WalkDir(scanRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Skip paths we can't access
			return nil
		}

		pathNorm := filepath.ToSlash(path)

		// Directory IoCs
		if d.IsDir() {
			if f := scanHostPathIOCs(dirIOCs, pathNorm); f != nil {
				findings = append(findings, *f)
			}
			return nil
		}

		// File IoCs and package.json scans
		if f := scanPackageJSON(maliciousPackages, path); f != nil {
			findings = append(findings, *f)
		}

		if f := scanHostPathIOCs(fileIOCs, pathNorm); f != nil {
			findings = append(findings, *f)
		}

		return nil
	})

	if err != nil {
		return findings, err
	}
	return findings, nil
}

func loadMaliciousNpmPackages() (map[string]string, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	malicious := make(map[string]string)

	fmt.Println("Fetching OSSF malicious package db...")
	if err := fetchOSSFMaliciousPackages(client, malicious); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to fetch OSSF's malicious package db: %v\n", err)
	}

	fmt.Println("Fetching RHIS malicious package db...")
	if err := fetchRHISMaliciousPackages(client, malicious); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to fetch RHIS's malicious package db: %v\n", err)
	}

	if len(malicious) == 0 {
		return nil, fmt.Errorf("unable to fetch any malicious package DBs")
	}

	return malicious, nil
}

func fetchOSSFMaliciousPackages(client *http.Client, malicious map[string]string) error {
	resp, err := client.Get(OSSFMalPackageDBURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	fmt.Println("Loading OSSF malicious package db...")
	scanner := bufio.NewScanner(resp.Body)
	context := "Source: OSSF Malicious Package DB"
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		malicious[line] = context
	}
	return scanner.Err()
}

func fetchRHISMaliciousPackages(client *http.Client, malicious map[string]string) error {
	resp, err := client.Get(RHISMalPackageDBURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	fmt.Println("Loading RHIS malicious package db...")
	reader := csv.NewReader(resp.Body)

	header, err := reader.Read()
	if err != nil {
		return err
	}

	indices := map[string]int{
		"package_name":    -1,
		"package_version": -1,
		"campaign_name":   -1,
	}
	for i, h := range header {
		switch strings.TrimSpace(strings.ToLower(h)) {
		case "package_name":
			indices["package_name"] = i
		case "package_version":
			indices["package_version"] = i
		case "campaign_name":
			indices["campaign_name"] = i
		}
	}

	for _, v := range indices {
		if v == -1 {
			return fmt.Errorf("missing expected columns in RHIS malicious package CSV")
		}
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		pkgName := record[indices["package_name"]]
		pkgVersion := record[indices["package_version"]]
		campaign := record[indices["campaign_name"]]

		if pkgName == "" || pkgVersion == "" {
			continue
		}

		pkgID := fmt.Sprintf("%s@%s", pkgName, pkgVersion)
		context := "Campaign: " + campaign
		malicious[pkgID] = context
	}

	return nil
}

func loadMaliciousPackageHostIOCs() ([]ioc, error) {
	fmt.Println("Fetching RHIS malicious package IOC db...")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(RHISMalPackageIOCDB)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	fmt.Println("Loading RHIS malicious package IOC db...")
	reader := csv.NewReader(resp.Body)

	header, err := reader.Read()
	if err != nil {
		return nil, err
	}

	colIdx := map[string]int{
		"ioc_type":        -1,
		"ioc_value":       -1,
		"ioc_description": -1,
		"campaign_name":   -1,
	}

	for i, h := range header {
		switch strings.TrimSpace(strings.ToLower(h)) {
		case "ioc_type":
			colIdx["ioc_type"] = i
		case "ioc_value":
			colIdx["ioc_value"] = i
		case "ioc_description":
			colIdx["ioc_description"] = i
		case "campaign_name":
			colIdx["campaign_name"] = i
		}
	}

	for _, v := range colIdx {
		if v == -1 {
			return nil, fmt.Errorf("missing expected columns in RHIS IOC CSV")
		}
	}

	var iocs []ioc
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		iocType := record[colIdx["ioc_type"]]
		value := record[colIdx["ioc_value"]]
		desc := record[colIdx["ioc_description"]]
		campaign := record[colIdx["campaign_name"]]

		if iocType == "" || value == "" {
			continue
		}

		// Expand ~ and translate glob to regex
		regex, err := globToRegex(value)
		if err != nil {
			// Skip invalid patterns
			continue
		}

		iocs = append(iocs, ioc{
			Type:        iocType,
			Pattern:     value,
			Regex:       regex,
			Description: desc,
			Campaign:    campaign,
		})
	}

	return iocs, nil
}

func scanPackageJSON(malicious map[string]string, path string) *finding {
	if filepath.Base(path) != "package.json" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	name := strings.ToLower(strings.TrimSpace(pkg.Name))
	version := strings.ToLower(strings.TrimSpace(pkg.Version))
	if name == "" || version == "" {
		return nil
	}

	pkgID := fmt.Sprintf("%s@%s", name, version)
	context, ok := malicious[pkgID]
	if !ok {
		return nil
	}

	return &finding{
		Path:    path,
		Finding: "Malicious Package: " + pkgID,
		Context: context,
	}
}

func scanHostPathIOCs(iocs []ioc, path string) *finding {
	for _, i := range iocs {
		if i.Regex != nil && i.Regex.MatchString(path) {
			return &finding{
				Path:    path,
				Finding: "IoC: " + i.Description,
				Context: "Campaign: " + i.Campaign,
			}
		}
	}
	return nil
}

// globToRegex does a simple translation from a glob-style pattern to a regexp.
// It supports:
//   - ?  -> any single character
//   - *  -> any number of non-separator characters
//   - ** -> any number of characters, including separators
//
// It normalizes path separators to '/'.
func globToRegex(pattern string) (*regexp.Regexp, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, fmt.Errorf("empty pattern")
	}

	// Expand ~ to user home where applicable
	if strings.HasPrefix(pattern, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			rest := strings.TrimPrefix(pattern, "~")
			// Avoid double separators
			if strings.HasPrefix(rest, "/") {
				pattern = filepath.ToSlash(filepath.Join(home, rest[1:]))
			} else {
				pattern = filepath.ToSlash(filepath.Join(home, rest))
			}
		}
	}

	// Normalize to forward slashes
	pattern = filepath.ToSlash(pattern)

	var b strings.Builder
	b.WriteString("^")

	metaChars := `.+()|^$[]{}\-`

	for i := 0; i < len(pattern); {
		c := pattern[i]

		switch c {
		case '*':
			// Check for **
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				b.WriteString(".*")
				i += 2
			} else {
				b.WriteString("[^/]*")
				i++
			}
		case '?':
			b.WriteString(".")
			i++
		default:
			if strings.ContainsRune(metaChars, rune(c)) {
				b.WriteByte('\\')
			}
			b.WriteByte(c)
			i++
		}
	}

	b.WriteString("$")
	return regexp.Compile(b.String())
}

func currentUsername() string {
	// Try common env vars first to avoid requiring os/user which may not work in all envs
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "unknown"
}

func currentHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}
