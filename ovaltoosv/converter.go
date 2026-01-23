//
// Copyright (c) Jeff Mendoza <jlm@jlm.name>
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// SPDX-License-Identifier: MIT
//

package ovaltoosv

import (
	"fmt"
	"strings"
	"time"

	"github.com/jeffmendoza/ovaltoosv/oval"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Converter handles OVAL to OSV conversion
type Converter struct {
	ovalData *oval.OvalDefinitions
	vulnMap  map[string]*osvschema.Vulnerability // keyed by vulnerability ID
}

// =============================================================================
// Public Methods
// =============================================================================

// NewConverter creates a new Converter
func NewConverter() *Converter {
	return &Converter{}
}

// ParseOVAL parses the OVAL input and stores it internally
func (c *Converter) ParseOVAL(input string) error {
	ovalData, err := oval.Parse(input)
	if err != nil {
		return err
	}
	c.ovalData = ovalData
	return nil
}

// ConvertToOSV converts the parsed OVAL to OSV format
func (c *Converter) ConvertToOSV() error {
	if c.ovalData == nil {
		return fmt.Errorf("no OVAL data to convert; call ParseOVAL first")
	}

	c.vulnMap = make(map[string]*osvschema.Vulnerability)

	if c.ovalData.Definitions == nil {
		return nil
	}

	// Use generator timestamp if available, otherwise use current time
	modified := c.parseTimestamp(c.ovalData.Generator.Timestamp)

	for _, def := range c.ovalData.Definitions.Definition {
		// Only process vulnerability class definitions
		if def.Class != "vulnerability" {
			continue
		}

		id := c.extractOSVID(def)

		if existing, ok := c.vulnMap[id]; ok {
			// Merge with existing vulnerability
			c.mergeDefinition(existing, def)
		} else {
			// Create new vulnerability
			vuln := c.convertDefinition(def, modified)
			c.vulnMap[id] = vuln
		}
	}

	return nil
}

// GetVulnerabilities returns the map of vulnerability IDs to vulnerabilities
func (c *Converter) GetVulnerabilities() map[string]*osvschema.Vulnerability {
	return c.vulnMap
}

// GetJSON returns a map of vulnerability IDs to their JSON representation
func (c *Converter) GetJSON() (map[string][]byte, error) {
	if len(c.vulnMap) == 0 {
		return nil, fmt.Errorf("no vulnerabilities to marshal; call ConvertToOSV first")
	}

	result := make(map[string][]byte)
	for id, vuln := range c.vulnMap {
		jsonBytes, err := protojson.MarshalOptions{
			Multiline: true,
			Indent:    "  ",
		}.Marshal(vuln)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal vulnerability %s: %w", id, err)
		}
		result[id] = jsonBytes
	}

	return result, nil
}

// =============================================================================
// Private Methods - Definition Conversion
// =============================================================================

// versionInfo holds extracted version information from OVAL criteria
type versionInfo struct {
	FixedVersion string // The version that fixes the vulnerability
	Operation    string // The comparison operation (e.g., "less than")
	Arch         string // Architecture (e.g., "x86_64", "aarch64")
	PurlType     string // Package URL type (e.g., "rpm", "deb") based on test type
}

// convertDefinition converts a single OVAL Definition to an OSV Vulnerability
func (c *Converter) convertDefinition(def oval.Definition, modified time.Time) *osvschema.Vulnerability {
	vuln := &osvschema.Vulnerability{
		SchemaVersion: osvconstants.SchemaVersion,
		Modified:      timestamppb.New(modified),
	}

	// Map OVAL Definition ID to OSV ID
	// OVAL IDs like "oval:com.microsoft.azurelinux:def:74153" -> use the numeric part or CVE if available
	vuln.Id = c.extractOSVID(def)

	// Map metadata fields
	vuln.Summary = def.Metadata.Title
	vuln.Details = def.Metadata.Description

	// Map references (CVE links, etc.)
	vuln.References = c.convertReferences(def.Metadata.Reference)

	// Extract aliases - exclude the primary ID to avoid duplication
	vuln.Aliases = c.extractAliases(def.Metadata.Reference, vuln.Id)

	// Map affected packages/platforms
	vuln.Affected = c.convertAffected(def)

	// Map severity if available from vendor metadata
	if def.Metadata.Severity != "" {
		vuln.Severity = c.convertSeverity(def.Metadata.Severity)
	}

	// Use advisory_date as published date if available
	if def.Metadata.AdvisoryDate != "" {
		if published := c.parseTimestamp(def.Metadata.AdvisoryDate); !published.IsZero() {
			vuln.Published = timestamppb.New(published)
		}
	}

	return vuln
}

// mergeDefinition merges a new OVAL definition into an existing OSV vulnerability
// This is used when the same CVE affects multiple packages
func (c *Converter) mergeDefinition(vuln *osvschema.Vulnerability, def oval.Definition) {
	// Merge affected packages
	newAffected := c.convertAffected(def)
	vuln.Affected = append(vuln.Affected, newAffected...)

	// Merge summary - append package-specific info if different
	if def.Metadata.Title != "" && def.Metadata.Title != vuln.Summary {
		// Extract just the package portion to avoid repetitive CVE mentions
		newPkg := extractPackageFromTitle(def.Metadata.Title)
		if newPkg != "" {
			existingPkg := extractPackageFromTitle(vuln.Summary)
			if existingPkg != "" && existingPkg != newPkg {
				// Update summary to be more generic, listing affected packages
				vuln.Summary = vuln.Id + " affecting multiple packages including " + existingPkg + ", " + newPkg
			}
		}
	}

	// Merge details - concatenate unique descriptions
	if def.Metadata.Description != "" && !strings.Contains(vuln.Details, def.Metadata.Description) {
		if vuln.Details != "" {
			vuln.Details = vuln.Details + "\n\n" + def.Metadata.Description
		} else {
			vuln.Details = def.Metadata.Description
		}
	}

	// Merge references (avoid duplicates)
	newRefs := c.convertReferences(def.Metadata.Reference)
	existingURLs := make(map[string]bool)
	for _, ref := range vuln.References {
		existingURLs[ref.Url] = true
	}
	for _, ref := range newRefs {
		if !existingURLs[ref.Url] {
			vuln.References = append(vuln.References, ref)
			existingURLs[ref.Url] = true
		}
	}

	// Merge aliases (avoid duplicates)
	newAliases := c.extractAliases(def.Metadata.Reference, vuln.Id)
	existingAliases := make(map[string]bool)
	for _, alias := range vuln.Aliases {
		existingAliases[alias] = true
	}
	for _, alias := range newAliases {
		if !existingAliases[alias] {
			vuln.Aliases = append(vuln.Aliases, alias)
			existingAliases[alias] = true
		}
	}
}

// =============================================================================
// Private Methods - ID and Reference Extraction
// =============================================================================

// extractOSVID determines the OSV ID from the OVAL definition
// Prefers CVE ID if available, otherwise uses the OVAL definition ID
func (c *Converter) extractOSVID(def oval.Definition) string {
	// First, check if there's a CVE reference
	for _, ref := range def.Metadata.Reference {
		if ref.Source == "CVE" && ref.RefID != "" {
			return ref.RefID
		}
	}

	// Fall back to OVAL definition ID
	// Convert "oval:com.microsoft.azurelinux:def:74153" to a usable ID
	return def.ID
}

// extractAliases extracts alternative vulnerability IDs from references
// excludeID is used to avoid duplicating the primary vulnerability ID
func (c *Converter) extractAliases(refs []oval.Reference, excludeID string) []string {
	var aliases []string
	seen := make(map[string]bool)
	seen[excludeID] = true // Don't include the primary ID as an alias

	for _, ref := range refs {
		if ref.RefID != "" && !seen[ref.RefID] {
			// Include all reference IDs as potential aliases
			aliases = append(aliases, ref.RefID)
			seen[ref.RefID] = true
		}
	}

	return aliases
}

// convertReferences converts OVAL references to OSV references
func (c *Converter) convertReferences(refs []oval.Reference) []*osvschema.Reference {
	var osvRefs []*osvschema.Reference

	for _, ref := range refs {
		if ref.RefURL == "" {
			continue
		}

		osvRef := &osvschema.Reference{
			Url:  ref.RefURL,
			Type: c.mapReferenceType(ref.Source),
		}
		osvRefs = append(osvRefs, osvRef)
	}

	return osvRefs
}

// mapReferenceType maps OVAL reference source to OSV reference type
func (c *Converter) mapReferenceType(source string) osvschema.Reference_Type {
	switch strings.ToUpper(source) {
	case "CVE":
		return osvschema.Reference_ADVISORY
	case "ADVISORY", "VENDOR":
		return osvschema.Reference_ADVISORY
	case "BUG", "BUGZILLA":
		return osvschema.Reference_REPORT
	case "PATCH", "FIX":
		return osvschema.Reference_FIX
	default:
		return osvschema.Reference_WEB
	}
}

// convertSeverity converts vendor severity string to OSV severity
// OSV schema requires CVSS vector strings (v2, v3, or v4) with a type field.
// Simple text severities like "medium" or "high" are not valid in the OSV schema,
// so we skip them entirely. In the future, if CVSS vectors are available in the
// OVAL data, they can be mapped here.
func (c *Converter) convertSeverity(severity string) []*osvschema.Severity {
	// For now, we don't output severity since OVAL only provides text labels
	// (e.g., "Medium", "High") which are not valid OSV severity values.
	// OSV requires CVSS vector strings like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	return nil
}

// =============================================================================
// Private Methods - Affected Package Conversion
// =============================================================================

// convertAffected converts OVAL affected information to OSV affected
func (c *Converter) convertAffected(def oval.Definition) []*osvschema.Affected {
	var affected []*osvschema.Affected

	// Extract version info from criteria
	versionInfo := c.extractVersionFromCriteria(def.Criteria)

	for _, aff := range def.Metadata.Affected {
		// Create an affected entry for each platform/product combination
		ecosystem := c.mapFamilyToEcosystem(aff.Family, aff.Platform)

		// Determine the PURL namespace from platforms
		var purlNamespace string
		if len(aff.Platform) > 0 {
			purlNamespace = mapPlatformToPurlNamespace(aff.Platform[0])
		}

		// Get distro string for PURL qualifier
		var distro string
		if len(aff.Platform) > 0 {
			distro = normalizePlatformToDistro(aff.Platform[0])
		}

		for _, product := range aff.Product {
			osvAff := &osvschema.Affected{
				Package: &osvschema.Package{
					Name:      product,
					Ecosystem: string(ecosystem),
				},
			}
			// Add PURL if we have version info and a known package type
			if versionInfo.FixedVersion != "" && versionInfo.PurlType != "" && purlNamespace != "" {
				osvAff.Package.Purl = buildPurl(versionInfo.PurlType, purlNamespace, product, versionInfo.FixedVersion, versionInfo.Arch, distro)
			}
			// Add version ranges if we found version info
			if versionInfo.FixedVersion != "" {
				osvAff.Ranges = c.createVersionRanges(versionInfo)
			}
			affected = append(affected, osvAff)
		}

		// If no products but platforms exist, create platform-based affected entries
		if len(aff.Product) == 0 && len(aff.Platform) > 0 {
			for _, platform := range aff.Platform {
				packageName := extractPackageFromTitle(def.Metadata.Title)
				namespace := mapPlatformToPurlNamespace(platform)
				platformDistro := normalizePlatformToDistro(platform)
				platformEcosystem := c.mapPlatformToEcosystem(platform)
				osvAff := &osvschema.Affected{
					Package: &osvschema.Package{
						Name:      packageName,
						Ecosystem: string(platformEcosystem),
					},
				}
				// Add PURL if we have version info and a known package type
				if versionInfo.FixedVersion != "" && versionInfo.PurlType != "" && namespace != "" {
					osvAff.Package.Purl = buildPurl(versionInfo.PurlType, namespace, packageName, versionInfo.FixedVersion, versionInfo.Arch, platformDistro)
				}
				// Add version ranges if we found version info
				if versionInfo.FixedVersion != "" {
					osvAff.Ranges = c.createVersionRanges(versionInfo)
				}
				affected = append(affected, osvAff)
			}
		}
	}

	return affected
}

// createVersionRanges creates OSV version ranges from extracted version info
func (c *Converter) createVersionRanges(info versionInfo) []*osvschema.Range {
	if info.FixedVersion == "" {
		return nil
	}

	// Create an ECOSYSTEM range with introduced=0 and fixed=version
	// This indicates all versions before the fixed version are affected
	return []*osvschema.Range{
		{
			Type: osvschema.Range_ECOSYSTEM,
			Events: []*osvschema.Event{
				{
					Introduced: "0",
				},
				{
					Fixed: info.FixedVersion,
				},
			},
		},
	}
}

// =============================================================================
// Private Methods - Version Extraction
// =============================================================================

// extractVersionFromCriteria extracts version information from OVAL criteria
// It first tries to resolve the test_ref to get the actual state with EVR,
// falling back to parsing criterion comments if the state is not available.
func (c *Converter) extractVersionFromCriteria(criteria *oval.Criteria) versionInfo {
	if criteria == nil {
		return versionInfo{}
	}

	// Check all criterion elements for version info
	for _, criterion := range criteria.Criterion {
		// Get version info from the actual test/state data
		if info := c.extractVersionFromTestRef(criterion.TestRef); info.FixedVersion != "" {
			return info
		}
	}

	// Recursively check nested criteria
	for _, nested := range criteria.Criteria {
		if info := c.extractVersionFromCriteria(&nested); info.FixedVersion != "" {
			return info
		}
	}

	return versionInfo{}
}

// extractVersionFromTestRef extracts version info by looking up the test and its state
// This provides more accurate version info than parsing comments
func (c *Converter) extractVersionFromTestRef(testRef string) versionInfo {
	if c.ovalData == nil || testRef == "" {
		return versionInfo{}
	}

	// Get the RPM info test (for Linux/RPM-based systems)
	rpmTest := c.ovalData.GetRPMInfoTest(testRef)
	if rpmTest != nil && len(rpmTest.State) > 0 {
		stateRef := rpmTest.State[0].StateRef
		state := c.ovalData.GetRPMInfoState(stateRef)
		if state != nil && state.EVR != nil {
			evr := state.EVR.Value
			version := normalizeEVR(evr)
			info := versionInfo{
				FixedVersion: version,
				Operation:    state.EVR.Operation,
				PurlType:     "rpm", // rpminfo_test -> pkg:rpm
			}
			// Extract architecture if available
			if state.Arch != nil && state.Arch.Value != "" {
				info.Arch = state.Arch.Value
			}
			return info
		}
	}

	// TODO: Add support for other test types:
	// - dpkginfo_test -> pkg:deb (Debian/Ubuntu)
	// - slackwarepkginfo_test -> pkg:slack (Slackware)

	// Fall back to generic test lookup
	test := c.ovalData.GetTest(testRef)
	if test == nil || len(test.State) == 0 {
		return versionInfo{}
	}

	// Get the state referenced by the test
	stateRef := test.State[0].StateRef
	state := c.ovalData.GetRPMInfoState(stateRef)
	if state == nil || state.EVR == nil {
		return versionInfo{}
	}

	// Extract version from EVR (format: "epoch:version-release")
	// e.g., "0:2.4.9-1.azl3" -> we want "2.4.9-1.azl3" or strip the distro suffix
	evr := state.EVR.Value
	version := normalizeEVR(evr)

	return versionInfo{
		FixedVersion: version,
		Operation:    state.EVR.Operation,
	}
}

// =============================================================================
// Private Methods - Ecosystem Mapping
// =============================================================================

// mapFamilyToEcosystem maps OVAL family to OSV ecosystem
func (c *Converter) mapFamilyToEcosystem(family string, platforms []string) osvconstants.Ecosystem {
	switch strings.ToLower(family) {
	case "unix", "linux":
		// Try to determine specific ecosystem from platforms
		for _, p := range platforms {
			if eco := c.mapPlatformToEcosystem(p); eco != "" {
				return eco
			}
		}
		return osvconstants.EcosystemLinux
	case "windows", "macos":
		// Windows and MacOS are not defined ecosystems in OSV schema
		// Fall back to Linux as generic ecosystem
		return osvconstants.EcosystemLinux
	default:
		return osvconstants.EcosystemLinux
	}
}

// mapPlatformToEcosystem maps OVAL platform to OSV ecosystem
// Returns only ecosystems defined in the OSV schema specification.
// For platforms without a specific ecosystem, returns EcosystemLinux as fallback.
func (c *Converter) mapPlatformToEcosystem(platform string) osvconstants.Ecosystem {
	platformLower := strings.ToLower(platform)

	switch {
	case strings.Contains(platformLower, "azure linux"):
		return osvconstants.EcosystemLinux
	case strings.Contains(platformLower, "debian"):
		return osvconstants.EcosystemDebian
	case strings.Contains(platformLower, "ubuntu"):
		return osvconstants.EcosystemUbuntu
	case strings.Contains(platformLower, "red hat"), strings.Contains(platformLower, "rhel"):
		return osvconstants.EcosystemRedHat
	case strings.Contains(platformLower, "centos"):
		// CentOS not in OSV schema, use Linux as fallback
		return osvconstants.EcosystemLinux
	case strings.Contains(platformLower, "fedora"):
		// Fedora not in OSV schema, use Linux as fallback
		return osvconstants.EcosystemLinux
	case strings.Contains(platformLower, "opensuse"):
		return osvconstants.EcosystemOpenSUSE
	case strings.Contains(platformLower, "suse"), strings.Contains(platformLower, "sles"):
		return osvconstants.EcosystemSUSE
	case strings.Contains(platformLower, "alpine"):
		return osvconstants.EcosystemAlpine
	case strings.Contains(platformLower, "oracle"):
		// Oracle Linux not in OSV schema, use Linux as fallback
		return osvconstants.EcosystemLinux
	case strings.Contains(platformLower, "alma"):
		return osvconstants.EcosystemAlmaLinux
	case strings.Contains(platformLower, "rocky"):
		return osvconstants.EcosystemRockyLinux
	case strings.Contains(platformLower, "photon"):
		return osvconstants.EcosystemPhotonOS
	case strings.Contains(platformLower, "wolfi"):
		return osvconstants.EcosystemWolfi
	case strings.Contains(platformLower, "chainguard"):
		return osvconstants.EcosystemChainguard
	case strings.Contains(platformLower, "mageia"):
		return osvconstants.EcosystemMageia
	case strings.Contains(platformLower, "freebsd"):
		return osvconstants.EcosystemFreeBSD
	case strings.Contains(platformLower, "android"):
		return osvconstants.EcosystemAndroid
	default:
		return osvconstants.EcosystemLinux
	}
}

// =============================================================================
// Private Methods - Timestamp Parsing
// =============================================================================

// parseTimestamp parses an OVAL timestamp string to time.Time
func (c *Converter) parseTimestamp(ts string) time.Time {
	// OVAL timestamps are typically in format: 2026-01-22T13:11:40.643166655Z
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02",
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, ts); err == nil {
			return t
		}
	}

	// Default to current time if parsing fails
	return time.Now().UTC()
}

// =============================================================================
// Private Helper Functions (standalone)
// =============================================================================

// normalizeEVR normalizes an EVR string for OSV output
// Input format: "epoch:version-release" (e.g., "0:2.4.9-1.azl3")
// Output: stripped version suitable for package version comparison
func normalizeEVR(evr string) string {
	// Remove epoch prefix if it's "0:" (common default)
	evr = strings.TrimPrefix(evr, "0:")

	// Optionally strip distribution suffix like ".azl3", ".el8", etc.
	// For now, keep it as-is since it's part of the package version
	return evr
}

// extractPackageFromTitle attempts to extract the package name from the definition title
// e.g., "CVE-2026-21441 affecting package tensorflow for versions less than 2.16.1-10"
func extractPackageFromTitle(title string) string {
	// Look for "package <name>" pattern
	if idx := strings.Index(title, "package "); idx != -1 {
		rest := title[idx+8:] // Skip "package "
		// Find the end of the package name (next space or "for")
		if endIdx := strings.Index(rest, " for "); endIdx != -1 {
			return rest[:endIdx]
		}
		if endIdx := strings.Index(rest, " "); endIdx != -1 {
			return rest[:endIdx]
		}
		return rest
	}
	return ""
}

// mapPlatformToPurlNamespace maps OVAL platform to PURL namespace
// The namespace is the vendor/distributor name in lowercase
func mapPlatformToPurlNamespace(platform string) string {
	platformLower := strings.ToLower(platform)

	switch {
	case strings.Contains(platformLower, "azure linux"):
		return "azurelinux"
	case strings.Contains(platformLower, "debian"):
		return "debian"
	case strings.Contains(platformLower, "ubuntu"):
		return "ubuntu"
	case strings.Contains(platformLower, "red hat"), strings.Contains(platformLower, "rhel"):
		return "redhat"
	case strings.Contains(platformLower, "centos"):
		return "centos"
	case strings.Contains(platformLower, "fedora"):
		return "fedora"
	case strings.Contains(platformLower, "opensuse"):
		return "opensuse"
	case strings.Contains(platformLower, "suse"), strings.Contains(platformLower, "sles"):
		return "suse"
	case strings.Contains(platformLower, "alpine"):
		return "alpine"
	case strings.Contains(platformLower, "oracle"):
		return "oracle"
	case strings.Contains(platformLower, "alma"):
		return "almalinux"
	case strings.Contains(platformLower, "rocky"):
		return "rocky"
	case strings.Contains(platformLower, "photon"):
		return "photon"
	case strings.Contains(platformLower, "wolfi"):
		return "wolfi"
	case strings.Contains(platformLower, "chainguard"):
		return "chainguard"
	case strings.Contains(platformLower, "mageia"):
		return "mageia"
	case strings.Contains(platformLower, "freebsd"):
		return "freebsd"
	case strings.Contains(platformLower, "android"):
		return "android"
	default:
		// Use the platform name as-is but lowercase
		return strings.ToLower(strings.ReplaceAll(platform, " ", ""))
	}
}

// normalizePlatformToDistro converts a platform string to a distro qualifier value
// e.g., "Azure Linux 3.0" -> "azurelinux-3.0", "Fedora 25" -> "fedora-25"
func normalizePlatformToDistro(platform string) string {
	// Convert to lowercase and replace spaces with hyphens
	distro := strings.ToLower(platform)
	distro = strings.ReplaceAll(distro, " ", "-")
	return distro
}

// buildPurl constructs a Package URL
// Format: pkg:type/namespace/name@version?arch=arch&distro=distro
func buildPurl(purlType, namespace, name, version, arch, distro string) string {
	qualifierMap := make(map[string]string)
	if arch != "" {
		qualifierMap["arch"] = arch
	}
	if distro != "" {
		qualifierMap["distro"] = distro
	}

	var qualifiers packageurl.Qualifiers
	if len(qualifierMap) > 0 {
		qualifiers = packageurl.QualifiersFromMap(qualifierMap)
	}

	purl := packageurl.NewPackageURL(
		purlType,  // type (rpm, deb, etc.)
		namespace, // namespace (distro)
		name,      // name
		version,   // version
		qualifiers,
		"", // subpath
	)

	return purl.ToString()
}
