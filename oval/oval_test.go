//
// Copyright (c) Jeff Mendoza <jlm@jlm.name>
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// SPDX-License-Identifier: MIT
//

package oval

import (
	"testing"
)

func TestParse_BasicDocument(t *testing.T) {
	input := `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
                  xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">
  <generator>
    <oval:product_name>Test Generator</oval:product_name>
    <oval:product_version>1.0.0</oval:product_version>
    <oval:schema_version>5.12.2</oval:schema_version>
    <oval:timestamp>2026-01-22T00:00:00</oval:timestamp>
  </generator>
  <definitions>
    <definition id="oval:org.example:def:1" version="1" class="vulnerability">
      <metadata>
        <title>Test Vulnerability Definition</title>
        <affected family="unix">
          <platform>Red Hat Enterprise Linux 9</platform>
          <product>httpd</product>
        </affected>
        <reference source="CVE" ref_id="CVE-2024-0001" ref_url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-0001"/>
        <description>A test vulnerability description for testing purposes.</description>
      </metadata>
      <criteria operator="AND">
        <criterion test_ref="oval:org.example:tst:1" comment="Check if httpd is installed"/>
        <criterion test_ref="oval:org.example:tst:2" comment="Check httpd version"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`

	oval, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if oval == nil {
		t.Fatal("Parse returned nil")
	}

	// Verify generator
	if oval.Generator.ProductName != "Test Generator" {
		t.Errorf("Generator.ProductName = %q, want %q", oval.Generator.ProductName, "Test Generator")
	}
	if oval.Generator.ProductVersion != "1.0.0" {
		t.Errorf("Generator.ProductVersion = %q, want %q", oval.Generator.ProductVersion, "1.0.0")
	}

	// Verify definitions
	if oval.Definitions == nil {
		t.Fatal("Definitions is nil")
	}
	if len(oval.Definitions.Definition) != 1 {
		t.Fatalf("len(Definitions.Definition) = %d, want 1", len(oval.Definitions.Definition))
	}

	def := oval.Definitions.Definition[0]
	if def.ID != "oval:org.example:def:1" {
		t.Errorf("Definition.ID = %q, want %q", def.ID, "oval:org.example:def:1")
	}
	if def.Version != 1 {
		t.Errorf("Definition.Version = %d, want 1", def.Version)
	}
	if def.Class != "vulnerability" {
		t.Errorf("Definition.Class = %q, want %q", def.Class, "vulnerability")
	}

	// Verify metadata
	if def.Metadata.Title != "Test Vulnerability Definition" {
		t.Errorf("Metadata.Title = %q, want %q", def.Metadata.Title, "Test Vulnerability Definition")
	}
	if def.Metadata.Description != "A test vulnerability description for testing purposes." {
		t.Errorf("Metadata.Description = %q, want %q", def.Metadata.Description, "A test vulnerability description for testing purposes.")
	}

	// Verify affected
	if len(def.Metadata.Affected) != 1 {
		t.Fatalf("len(Metadata.Affected) = %d, want 1", len(def.Metadata.Affected))
	}
	affected := def.Metadata.Affected[0]
	if affected.Family != "unix" {
		t.Errorf("Affected.Family = %q, want %q", affected.Family, "unix")
	}
	if len(affected.Platform) != 1 || affected.Platform[0] != "Red Hat Enterprise Linux 9" {
		t.Errorf("Affected.Platform = %v, want [Red Hat Enterprise Linux 9]", affected.Platform)
	}

	// Verify reference
	if len(def.Metadata.Reference) != 1 {
		t.Fatalf("len(Metadata.Reference) = %d, want 1", len(def.Metadata.Reference))
	}
	ref := def.Metadata.Reference[0]
	if ref.Source != "CVE" {
		t.Errorf("Reference.Source = %q, want %q", ref.Source, "CVE")
	}
	if ref.RefID != "CVE-2024-0001" {
		t.Errorf("Reference.RefID = %q, want %q", ref.RefID, "CVE-2024-0001")
	}

	// Verify criteria
	if def.Criteria == nil {
		t.Fatal("Criteria is nil")
	}
	if def.Criteria.Operator != "AND" {
		t.Errorf("Criteria.Operator = %q, want %q", def.Criteria.Operator, "AND")
	}
	if len(def.Criteria.Criterion) != 2 {
		t.Fatalf("len(Criteria.Criterion) = %d, want 2", len(def.Criteria.Criterion))
	}
}

func TestParse_EmptyInput(t *testing.T) {
	_, err := Parse("")
	if err == nil {
		t.Error("Parse should return error for empty input")
	}
}

func TestParse_InvalidXML(t *testing.T) {
	_, err := Parse("<not valid xml")
	if err == nil {
		t.Error("Parse should return error for invalid XML")
	}
}

func TestParse_MultipleDefinitions(t *testing.T) {
	input := `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <generator>
    <schema_version>5.12.2</schema_version>
    <timestamp>2026-01-22T00:00:00</timestamp>
  </generator>
  <definitions>
    <definition id="oval:org.example:def:1" version="1" class="vulnerability">
      <metadata>
        <title>First Definition</title>
        <description>First description</description>
      </metadata>
    </definition>
    <definition id="oval:org.example:def:2" version="2" class="patch">
      <metadata>
        <title>Second Definition</title>
        <description>Second description</description>
      </metadata>
    </definition>
  </definitions>
</oval_definitions>`

	oval, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if oval.Definitions == nil || len(oval.Definitions.Definition) != 2 {
		t.Fatalf("Expected 2 definitions, got %v", oval.Definitions)
	}

	if oval.Definitions.Definition[0].Metadata.Title != "First Definition" {
		t.Errorf("First definition title = %q, want %q", oval.Definitions.Definition[0].Metadata.Title, "First Definition")
	}
	if oval.Definitions.Definition[1].Class != "patch" {
		t.Errorf("Second definition class = %q, want %q", oval.Definitions.Definition[1].Class, "patch")
	}
}

func TestParseBytes(t *testing.T) {
	input := []byte(`<?xml version="1.0"?>
<oval_definitions>
  <generator>
    <schema_version>5.12.2</schema_version>
    <timestamp>2026-01-22T00:00:00</timestamp>
  </generator>
</oval_definitions>`)

	oval, err := ParseBytes(input)
	if err != nil {
		t.Fatalf("ParseBytes returned error: %v", err)
	}

	if oval == nil {
		t.Fatal("ParseBytes returned nil")
	}
}

func TestParse_AzureLinuxSnippet(t *testing.T) {
	// Real snippet from azurelinux-3.0-oval.xml
	input := `<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <generator>
    <oval:product_name>Azure Linux OVAL Definition Generator</oval:product_name>
    <oval:product_version>19</oval:product_version>
    <oval:schema_version>5.11</oval:schema_version>
    <oval:timestamp>2026-01-22T13:11:40.643166655Z</oval:timestamp>
  </generator>
  <definitions>
    <definition class="vulnerability" id="oval:com.microsoft.azurelinux:def:74153" version="1">
      <metadata>
        <title>CVE-2026-21441 affecting package tensorflow for versions less than 2.16.1-10</title>
        <affected family="unix">
          <platform>Azure Linux</platform>
        </affected>
        <reference ref_id="CVE-2026-21441" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2026-21441" source="CVE"/>
        <patchable>true</patchable>
        <advisory_date>2026-01-20T21:31:32Z</advisory_date>
        <advisory_id>74153-1</advisory_id>
        <severity>High</severity>
        <description>CVE-2026-21441 affecting package tensorflow for versions less than 2.16.1-10. A patched version of the package is available.</description>
      </metadata>
      <criteria operator="AND">
        <criterion comment="Package tensorflow is earlier than 2.16.1-10, affected by CVE-2026-21441" test_ref="oval:com.microsoft.azurelinux:tst:74153000"/>
      </criteria>
    </definition>
    <definition class="vulnerability" id="oval:com.microsoft.azurelinux:def:73904" version="1">
      <metadata>
        <title>CVE-2025-69195 affecting package wget for versions less than 2.1.0-7</title>
        <affected family="unix">
          <platform>Azure Linux</platform>
        </affected>
        <reference ref_id="CVE-2025-69195" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2025-69195" source="CVE"/>
        <patchable>true</patchable>
        <advisory_date>2026-01-20T21:41:23Z</advisory_date>
        <advisory_id>73904-1</advisory_id>
        <severity>High</severity>
        <description>CVE-2025-69195 affecting package wget for versions less than 2.1.0-7. A patched version of the package is available.</description>
      </metadata>
      <criteria operator="AND">
        <criterion comment="Package wget is earlier than 2.1.0-7, affected by CVE-2025-69195" test_ref="oval:com.microsoft.azurelinux:tst:73904000"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`

	oval, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	// Verify generator
	if oval.Generator.ProductName != "Azure Linux OVAL Definition Generator" {
		t.Errorf("Generator.ProductName = %q, want %q", oval.Generator.ProductName, "Azure Linux OVAL Definition Generator")
	}
	if oval.Generator.ProductVersion != "19" {
		t.Errorf("Generator.ProductVersion = %q, want %q", oval.Generator.ProductVersion, "19")
	}
	if len(oval.Generator.SchemaVersion) == 0 || oval.Generator.SchemaVersion[0].Value != "5.11" {
		t.Errorf("Generator.SchemaVersion = %v, want 5.11", oval.Generator.SchemaVersion)
	}

	// Verify definitions count
	if oval.Definitions == nil {
		t.Fatal("Definitions is nil")
	}
	if len(oval.Definitions.Definition) != 2 {
		t.Fatalf("len(Definitions.Definition) = %d, want 2", len(oval.Definitions.Definition))
	}

	// Verify first definition (tensorflow CVE)
	def1 := oval.Definitions.Definition[0]
	if def1.ID != "oval:com.microsoft.azurelinux:def:74153" {
		t.Errorf("def1.ID = %q, want %q", def1.ID, "oval:com.microsoft.azurelinux:def:74153")
	}
	if def1.Class != "vulnerability" {
		t.Errorf("def1.Class = %q, want %q", def1.Class, "vulnerability")
	}
	if def1.Version != 1 {
		t.Errorf("def1.Version = %d, want 1", def1.Version)
	}

	// Verify metadata
	expectedTitle := "CVE-2026-21441 affecting package tensorflow for versions less than 2.16.1-10"
	if def1.Metadata.Title != expectedTitle {
		t.Errorf("def1.Metadata.Title = %q, want %q", def1.Metadata.Title, expectedTitle)
	}

	// Verify affected
	if len(def1.Metadata.Affected) != 1 {
		t.Fatalf("len(def1.Metadata.Affected) = %d, want 1", len(def1.Metadata.Affected))
	}
	if def1.Metadata.Affected[0].Family != "unix" {
		t.Errorf("Affected.Family = %q, want %q", def1.Metadata.Affected[0].Family, "unix")
	}
	if len(def1.Metadata.Affected[0].Platform) != 1 || def1.Metadata.Affected[0].Platform[0] != "Azure Linux" {
		t.Errorf("Affected.Platform = %v, want [Azure Linux]", def1.Metadata.Affected[0].Platform)
	}

	// Verify reference (CVE)
	if len(def1.Metadata.Reference) != 1 {
		t.Fatalf("len(def1.Metadata.Reference) = %d, want 1", len(def1.Metadata.Reference))
	}
	ref := def1.Metadata.Reference[0]
	if ref.Source != "CVE" {
		t.Errorf("Reference.Source = %q, want %q", ref.Source, "CVE")
	}
	if ref.RefID != "CVE-2026-21441" {
		t.Errorf("Reference.RefID = %q, want %q", ref.RefID, "CVE-2026-21441")
	}
	if ref.RefURL != "https://nvd.nist.gov/vuln/detail/CVE-2026-21441" {
		t.Errorf("Reference.RefURL = %q, want %q", ref.RefURL, "https://nvd.nist.gov/vuln/detail/CVE-2026-21441")
	}

	// Verify criteria
	if def1.Criteria == nil {
		t.Fatal("def1.Criteria is nil")
	}
	if def1.Criteria.Operator != "AND" {
		t.Errorf("Criteria.Operator = %q, want %q", def1.Criteria.Operator, "AND")
	}
	if len(def1.Criteria.Criterion) != 1 {
		t.Fatalf("len(Criteria.Criterion) = %d, want 1", len(def1.Criteria.Criterion))
	}
	criterion := def1.Criteria.Criterion[0]
	if criterion.TestRef != "oval:com.microsoft.azurelinux:tst:74153000" {
		t.Errorf("Criterion.TestRef = %q, want %q", criterion.TestRef, "oval:com.microsoft.azurelinux:tst:74153000")
	}
	expectedComment := "Package tensorflow is earlier than 2.16.1-10, affected by CVE-2026-21441"
	if criterion.Comment != expectedComment {
		t.Errorf("Criterion.Comment = %q, want %q", criterion.Comment, expectedComment)
	}

	// Verify second definition (wget CVE)
	def2 := oval.Definitions.Definition[1]
	if def2.ID != "oval:com.microsoft.azurelinux:def:73904" {
		t.Errorf("def2.ID = %q, want %q", def2.ID, "oval:com.microsoft.azurelinux:def:73904")
	}
	if def2.Metadata.Reference[0].RefID != "CVE-2025-69195" {
		t.Errorf("def2 CVE = %q, want %q", def2.Metadata.Reference[0].RefID, "CVE-2025-69195")
	}
}

func TestParse_RPMInfoStateWithEVR(t *testing.T) {
	// Test parsing rpminfo_state with EVR (epoch:version-release)
	input := `<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
                  xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <generator>
    <schema_version>5.11</schema_version>
    <timestamp>2026-01-22T00:00:00Z</timestamp>
  </generator>
  <tests>
    <linux-def:rpminfo_test check="at least one" comment="Package gnupg2 is earlier than 2.4.9-1" id="oval:com.microsoft.azurelinux:tst:73204000" version="1">
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

	oval, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	// Verify states were parsed
	if oval.States == nil {
		t.Fatal("States is nil")
	}
	if len(oval.States.RPMInfoState) != 1 {
		t.Fatalf("len(States.RPMInfoState) = %d, want 1", len(oval.States.RPMInfoState))
	}

	state := oval.States.RPMInfoState[0]
	if state.ID != "oval:com.microsoft.azurelinux:ste:73204002" {
		t.Errorf("State.ID = %q, want %q", state.ID, "oval:com.microsoft.azurelinux:ste:73204002")
	}
	if state.EVR == nil {
		t.Fatal("State.EVR is nil")
	}
	if state.EVR.Value != "0:2.4.9-1.azl3" {
		t.Errorf("State.EVR.Value = %q, want %q", state.EVR.Value, "0:2.4.9-1.azl3")
	}
	if state.EVR.Operation != "less than" {
		t.Errorf("State.EVR.Operation = %q, want %q", state.EVR.Operation, "less than")
	}
	if state.EVR.Datatype != "evr_string" {
		t.Errorf("State.EVR.Datatype = %q, want %q", state.EVR.Datatype, "evr_string")
	}

	// Verify objects were parsed
	if oval.Objects == nil {
		t.Fatal("Objects is nil")
	}
	if len(oval.Objects.RPMInfoObject) != 1 {
		t.Fatalf("len(Objects.RPMInfoObject) = %d, want 1", len(oval.Objects.RPMInfoObject))
	}

	obj := oval.Objects.RPMInfoObject[0]
	if obj.ID != "oval:com.microsoft.azurelinux:obj:73204001" {
		t.Errorf("Object.ID = %q, want %q", obj.ID, "oval:com.microsoft.azurelinux:obj:73204001")
	}
	if obj.Name != "gnupg2" {
		t.Errorf("Object.Name = %q, want %q", obj.Name, "gnupg2")
	}

	// Test helper methods
	foundState := oval.GetRPMInfoState("oval:com.microsoft.azurelinux:ste:73204002")
	if foundState == nil {
		t.Error("GetRPMInfoState returned nil for existing state")
	}
	if foundState != nil && foundState.EVR.Value != "0:2.4.9-1.azl3" {
		t.Errorf("GetRPMInfoState returned wrong state")
	}

	notFoundState := oval.GetRPMInfoState("nonexistent")
	if notFoundState != nil {
		t.Error("GetRPMInfoState should return nil for nonexistent state")
	}

	foundObj := oval.GetRPMInfoObject("oval:com.microsoft.azurelinux:obj:73204001")
	if foundObj == nil {
		t.Error("GetRPMInfoObject returned nil for existing object")
	}
	if foundObj != nil && foundObj.Name != "gnupg2" {
		t.Errorf("GetRPMInfoObject returned wrong object")
	}
}
