//
// Copyright (c) Jeff Mendoza <jlm@jlm.name>
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// SPDX-License-Identifier: MIT
//

package ovaltoosv

import (
	"strings"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

// Small example OVAL document for testing
const testOVAL = `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <generator>
    <schema_version>5.11</schema_version>
    <timestamp>2026-01-22T00:00:00</timestamp>
  </generator>
  <definitions>
    <definition id="oval:org.example:def:1" version="1" class="vulnerability">
      <metadata>
        <title>Test Vulnerability</title>
        <description>A test vulnerability description.</description>
        <reference source="CVE" ref_id="CVE-2026-12345" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2026-12345"/>
        <affected family="unix">
          <platform>Azure Linux</platform>
        </affected>
        <severity>High</severity>
        <advisory_date>2026-01-20T21:31:32Z</advisory_date>
      </metadata>
    </definition>
  </definitions>
</oval_definitions>`

func TestNewConverter(t *testing.T) {
	c := NewConverter()
	if c == nil {
		t.Fatal("NewConverter returned nil")
	}
}

func TestParseOVAL(t *testing.T) {
	c := NewConverter()

	err := c.ParseOVAL(testOVAL)
	if err != nil {
		t.Fatalf("ParseOVAL returned error: %v", err)
	}
}

func TestParseOVAL_InvalidInput(t *testing.T) {
	c := NewConverter()

	err := c.ParseOVAL("<invalid>not valid oval")
	if err == nil {
		t.Fatal("ParseOVAL should return error for invalid input")
	}
}

func TestConvertToOSV(t *testing.T) {
	c := NewConverter()

	err := c.ParseOVAL(testOVAL)
	if err != nil {
		t.Fatalf("ParseOVAL returned error: %v", err)
	}

	err = c.ConvertToOSV()
	if err != nil {
		t.Fatalf("ConvertToOSV returned error: %v", err)
	}

	output, err := c.GetJSON()
	if err != nil {
		t.Fatalf("GetJSON returned error: %v", err)
	}

	// Should have one vulnerability
	if len(output) != 1 {
		t.Fatalf("Expected 1 vulnerability, got %d", len(output))
	}

	// Get the JSON for CVE-2026-12345
	jsonBytes, ok := output["CVE-2026-12345"]
	if !ok {
		t.Fatal("Expected CVE-2026-12345 in output")
	}

	// Verify output is valid JSON and contains the description in Details field
	var vuln osvschema.Vulnerability
	if err := protojson.Unmarshal(jsonBytes, &vuln); err != nil {
		t.Fatalf("GetJSON output is not valid JSON: %v", err)
	}

	expectedDetails := "A test vulnerability description."
	if vuln.Details != expectedDetails {
		t.Errorf("Details field mismatch: got %q, want %q", vuln.Details, expectedDetails)
	}

	// Verify CVE ID is extracted
	if vuln.Id != "CVE-2026-12345" {
		t.Errorf("Id field mismatch: got %q, want %q", vuln.Id, "CVE-2026-12345")
	}

	// Verify summary is set from title
	if vuln.Summary != "Test Vulnerability" {
		t.Errorf("Summary field mismatch: got %q, want %q", vuln.Summary, "Test Vulnerability")
	}

	// Verify aliases don't include the primary ID
	for _, alias := range vuln.Aliases {
		if alias == vuln.Id {
			t.Errorf("Aliases should not include the primary ID %q", vuln.Id)
		}
	}

	// Severity is not output because OVAL only provides text labels (not CVSS vectors)
	// which are not valid in the OSV schema
	if len(vuln.Severity) != 0 {
		t.Error("Severity should not be set (text labels are not valid OSV severity)")
	}

	// Verify published date is set from advisory_date
	if vuln.Published == nil {
		t.Error("Published date should be set from advisory_date")
	}
}

func TestConvertToOSV_NoOVALData(t *testing.T) {
	c := NewConverter()

	err := c.ConvertToOSV()
	if err == nil {
		t.Fatal("ConvertToOSV should return error when no OVAL data is parsed")
	}
}

func TestConvertToOSV_MultipleDefinitions(t *testing.T) {
	multiDefOVAL := `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <generator>
    <schema_version>5.11</schema_version>
    <timestamp>2026-01-22T00:00:00Z</timestamp>
  </generator>
  <definitions>
    <definition id="oval:org.example:def:1" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2026-0001 affecting package foo</title>
        <description>First vulnerability.</description>
        <reference source="CVE" ref_id="CVE-2026-0001" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2026-0001"/>
        <affected family="unix">
          <platform>Azure Linux</platform>
        </affected>
      </metadata>
    </definition>
    <definition id="oval:org.example:def:2" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2026-0002 affecting package bar</title>
        <description>Second vulnerability.</description>
        <reference source="CVE" ref_id="CVE-2026-0002" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2026-0002"/>
        <affected family="unix">
          <platform>Debian</platform>
        </affected>
      </metadata>
    </definition>
  </definitions>
</oval_definitions>`

	c := NewConverter()
	err := c.ParseOVAL(multiDefOVAL)
	if err != nil {
		t.Fatalf("ParseOVAL returned error: %v", err)
	}

	err = c.ConvertToOSV()
	if err != nil {
		t.Fatalf("ConvertToOSV returned error: %v", err)
	}

	vulns := c.GetVulnerabilities()
	if len(vulns) != 2 {
		t.Fatalf("Expected 2 vulnerabilities, got %d", len(vulns))
	}

	// Verify vulnerabilities exist by ID
	if _, ok := vulns["CVE-2026-0001"]; !ok {
		t.Error("Expected CVE-2026-0001 in vulnerabilities")
	}

	if _, ok := vulns["CVE-2026-0002"]; !ok {
		t.Error("Expected CVE-2026-0002 in vulnerabilities")
	}

	// Verify GetJSON returns map with both entries
	output, err := c.GetJSON()
	if err != nil {
		t.Fatalf("GetJSON returned error: %v", err)
	}

	if len(output) != 2 {
		t.Errorf("Expected 2 JSON entries, got %d", len(output))
	}
}

func TestConvertToOSV_MergesSameCVE(t *testing.T) {
	// Test that vulnerabilities with the same CVE ID are merged
	sameCVEOVAL := `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <generator>
    <schema_version>5.11</schema_version>
    <timestamp>2026-01-22T00:00:00Z</timestamp>
  </generator>
  <definitions>
    <definition id="oval:org.example:def:1" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2026-21441 affecting package tensorflow for versions less than 2.16.1-10</title>
        <description>CVE-2026-21441 affecting package tensorflow.</description>
        <reference source="CVE" ref_id="CVE-2026-21441" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2026-21441"/>
        <affected family="unix">
          <platform>Azure Linux</platform>
        </affected>
      </metadata>
    </definition>
    <definition id="oval:org.example:def:2" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2026-21441 affecting package python-urllib3 for versions less than 2.0.7-4</title>
        <description>CVE-2026-21441 affecting package python-urllib3.</description>
        <reference source="CVE" ref_id="CVE-2026-21441" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2026-21441"/>
        <affected family="unix">
          <platform>Azure Linux</platform>
        </affected>
      </metadata>
    </definition>
  </definitions>
</oval_definitions>`

	c := NewConverter()
	err := c.ParseOVAL(sameCVEOVAL)
	if err != nil {
		t.Fatalf("ParseOVAL returned error: %v", err)
	}

	err = c.ConvertToOSV()
	if err != nil {
		t.Fatalf("ConvertToOSV returned error: %v", err)
	}

	vulns := c.GetVulnerabilities()
	if len(vulns) != 1 {
		t.Fatalf("Expected 1 merged vulnerability, got %d", len(vulns))
	}

	// Get the merged vulnerability
	vuln, ok := vulns["CVE-2026-21441"]
	if !ok {
		t.Fatal("Expected CVE-2026-21441 in vulnerabilities")
	}

	// Verify the merged vulnerability has both affected packages
	if len(vuln.Affected) != 2 {
		t.Fatalf("Expected 2 affected packages, got %d", len(vuln.Affected))
	}

	// Verify both packages are present
	packages := make(map[string]bool)
	for _, aff := range vuln.Affected {
		packages[aff.Package.Name] = true
	}

	if !packages["tensorflow"] {
		t.Error("Expected tensorflow in affected packages")
	}
	if !packages["python-urllib3"] {
		t.Error("Expected python-urllib3 in affected packages")
	}

	// Verify summary was merged to be more generic
	if !strings.Contains(vuln.Summary, "multiple packages") {
		t.Errorf("Expected summary to mention multiple packages, got: %q", vuln.Summary)
	}

	// Verify details contains info from both definitions
	if !strings.Contains(vuln.Details, "tensorflow") {
		t.Error("Expected details to mention tensorflow")
	}
	if !strings.Contains(vuln.Details, "python-urllib3") {
		t.Error("Expected details to mention python-urllib3")
	}

	// Verify we only have one reference (no duplicates)
	if len(vuln.References) != 1 {
		t.Errorf("Expected 1 reference (no duplicates), got %d", len(vuln.References))
	}
}

func TestExtractPackageFromTitle(t *testing.T) {
	tests := []struct {
		title    string
		expected string
	}{
		{
			title:    "CVE-2026-21441 affecting package tensorflow for versions less than 2.16.1-10",
			expected: "tensorflow",
		},
		{
			title:    "CVE-2025-69195 affecting package wget for versions less than 2.1.0-7",
			expected: "wget",
		},
		{
			title:    "Some other title format",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			result := extractPackageFromTitle(tt.title)
			if result != tt.expected {
				t.Errorf("extractPackageFromTitle(%q) = %q, want %q", tt.title, result, tt.expected)
			}
		})
	}
}

func TestConvertAffectedWithVersionRangesFromState(t *testing.T) {
	// Test that version extraction works from actual test/state data
	ovalWithFullData := `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
                  xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <generator>
    <schema_version>5.11</schema_version>
    <timestamp>2026-01-22T00:00:00Z</timestamp>
  </generator>
  <definitions>
    <definition id="oval:com.microsoft.azurelinux:def:73204" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2025-68973 affecting package gnupg2 for versions less than 2.4.9-1</title>
        <description>CVE-2025-68973 affecting package gnupg2.</description>
        <reference source="CVE" ref_id="CVE-2025-68973" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2025-68973"/>
        <affected family="unix">
          <platform>Azure Linux</platform>
        </affected>
      </metadata>
      <criteria operator="AND">
        <criterion comment="Package gnupg2 check" test_ref="oval:com.microsoft.azurelinux:tst:73204000"/>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <linux-def:rpminfo_test check="at least one" comment="Package gnupg2 check" id="oval:com.microsoft.azurelinux:tst:73204000" version="1">
      <linux-def:object object_ref="oval:com.microsoft.azurelinux:obj:73204001"/>
      <linux-def:state state_ref="oval:com.microsoft.azurelinux:ste:73204002"/>
    </linux-def:rpminfo_test>
  </tests>
  <objects>
    <linux-def:rpminfo_object id="oval:com.microsoft.azurelinux:obj:73204001" version="1">
      <linux-def:name>gnupg2</linux-def:name>
    </linux-def:rpminfo_object>
  </objects>
  <states>
    <linux-def:rpminfo_state id="oval:com.microsoft.azurelinux:ste:73204002" version="1">
      <linux-def:evr datatype="evr_string" operation="less than">0:2.4.9-1.azl3</linux-def:evr>
    </linux-def:rpminfo_state>
  </states>
</oval_definitions>`

	c := NewConverter()
	err := c.ParseOVAL(ovalWithFullData)
	if err != nil {
		t.Fatalf("ParseOVAL returned error: %v", err)
	}

	err = c.ConvertToOSV()
	if err != nil {
		t.Fatalf("ConvertToOSV returned error: %v", err)
	}

	vulns := c.GetVulnerabilities()
	vuln, ok := vulns["CVE-2025-68973"]
	if !ok {
		t.Fatal("Expected CVE-2025-68973 in vulnerabilities")
	}

	// Verify affected has version ranges from the actual state
	if len(vuln.Affected) == 0 {
		t.Fatal("Expected at least one affected entry")
	}

	affected := vuln.Affected[0]
	if len(affected.Ranges) == 0 {
		t.Fatal("Expected version ranges in affected")
	}

	rang := affected.Ranges[0]

	// The version should come from the EVR in the state (with epoch stripped)
	// "0:2.4.9-1.azl3" -> "2.4.9-1.azl3"
	if rang.Events[1].Fixed != "2.4.9-1.azl3" {
		t.Errorf("Expected fixed=2.4.9-1.azl3 (from state EVR), got %q", rang.Events[1].Fixed)
	}
}

func TestConvertAffectedWithPurl(t *testing.T) {
	// Test PURL generation with version and arch info
	ovalWithArch := `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <generator>
    <schema_version>5.11</schema_version>
    <timestamp>2026-01-22T00:00:00Z</timestamp>
  </generator>
  <definitions>
    <definition id="oval:com.example:def:1" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2025-12345 affecting package openssl</title>
        <description>CVE-2025-12345 affecting openssl.</description>
        <reference source="CVE" ref_id="CVE-2025-12345" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2025-12345"/>
        <affected family="unix">
          <platform>Azure Linux</platform>
        </affected>
      </metadata>
      <criteria operator="AND">
        <criterion comment="Package openssl is earlier than 3.0.13-6" test_ref="oval:com.example:tst:1"/>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <linux-def:rpminfo_test id="oval:com.example:tst:1" version="1" check="at least one" comment="openssl check">
      <linux-def:object object_ref="oval:com.example:obj:1"/>
      <linux-def:state state_ref="oval:com.example:ste:1"/>
    </linux-def:rpminfo_test>
  </tests>
  <objects>
    <linux-def:rpminfo_object id="oval:com.example:obj:1" version="1">
      <linux-def:name>openssl</linux-def:name>
    </linux-def:rpminfo_object>
  </objects>
  <states>
    <linux-def:rpminfo_state id="oval:com.example:ste:1" version="1">
      <linux-def:evr datatype="evr_string" operation="less than">0:3.0.13-6.azl3</linux-def:evr>
      <linux-def:arch>x86_64</linux-def:arch>
    </linux-def:rpminfo_state>
  </states>
</oval_definitions>`

	c := NewConverter()
	err := c.ParseOVAL(ovalWithArch)
	if err != nil {
		t.Fatalf("ParseOVAL returned error: %v", err)
	}

	err = c.ConvertToOSV()
	if err != nil {
		t.Fatalf("ConvertToOSV returned error: %v", err)
	}

	vulns := c.GetVulnerabilities()
	vuln, ok := vulns["CVE-2025-12345"]
	if !ok {
		t.Fatal("Expected CVE-2025-12345 in vulnerabilities")
	}

	if len(vuln.Affected) == 0 {
		t.Fatal("Expected at least one affected entry")
	}

	affected := vuln.Affected[0]

	// Verify PURL is generated correctly with arch and distro
	expectedPurl := "pkg:rpm/azurelinux/openssl@3.0.13-6.azl3?arch=x86_64&distro=azure-linux"
	if affected.Package.Purl != expectedPurl {
		t.Errorf("Expected purl=%q, got %q", expectedPurl, affected.Package.Purl)
	}
}

func TestConvertAffectedWithPurlNoArch(t *testing.T) {
	// Test PURL generation without arch info
	ovalWithoutArch := `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <generator>
    <schema_version>5.11</schema_version>
    <timestamp>2026-01-22T00:00:00Z</timestamp>
  </generator>
  <definitions>
    <definition id="oval:com.example:def:2" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2025-12346 affecting package curl</title>
        <description>CVE-2025-12346 affecting curl.</description>
        <reference source="CVE" ref_id="CVE-2025-12346" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2025-12346"/>
        <affected family="unix">
          <platform>Fedora</platform>
        </affected>
      </metadata>
      <criteria operator="AND">
        <criterion comment="Package curl is earlier than 7.50.3-1" test_ref="oval:com.example:tst:2"/>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <linux-def:rpminfo_test id="oval:com.example:tst:2" version="1" check="at least one" comment="curl check">
      <linux-def:object object_ref="oval:com.example:obj:2"/>
      <linux-def:state state_ref="oval:com.example:ste:2"/>
    </linux-def:rpminfo_test>
  </tests>
  <objects>
    <linux-def:rpminfo_object id="oval:com.example:obj:2" version="1">
      <linux-def:name>curl</linux-def:name>
    </linux-def:rpminfo_object>
  </objects>
  <states>
    <linux-def:rpminfo_state id="oval:com.example:ste:2" version="1">
      <linux-def:evr datatype="evr_string" operation="less than">0:7.50.3-1.fc25</linux-def:evr>
    </linux-def:rpminfo_state>
  </states>
</oval_definitions>`

	c := NewConverter()
	err := c.ParseOVAL(ovalWithoutArch)
	if err != nil {
		t.Fatalf("ParseOVAL returned error: %v", err)
	}

	err = c.ConvertToOSV()
	if err != nil {
		t.Fatalf("ConvertToOSV returned error: %v", err)
	}

	vulns := c.GetVulnerabilities()
	vuln, ok := vulns["CVE-2025-12346"]
	if !ok {
		t.Fatal("Expected CVE-2025-12346 in vulnerabilities")
	}

	if len(vuln.Affected) == 0 {
		t.Fatal("Expected at least one affected entry")
	}

	affected := vuln.Affected[0]

	// Verify PURL is generated with distro qualifier (no arch)
	expectedPurl := "pkg:rpm/fedora/curl@7.50.3-1.fc25?distro=fedora"
	if affected.Package.Purl != expectedPurl {
		t.Errorf("Expected purl=%q, got %q", expectedPurl, affected.Package.Purl)
	}
}
