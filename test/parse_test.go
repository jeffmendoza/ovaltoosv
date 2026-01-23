//
// Copyright (c) Jeff Mendoza <jlm@jlm.name>
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// SPDX-License-Identifier: MIT
//

package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeffmendoza/ovaltoosv/oval"
)

func TestParseAzureLinuxOVAL(t *testing.T) {
	// Get the path to the test file
	testFile := filepath.Join("azurelinux-3.0-oval.xml")

	// Read the file
	data, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	// Parse the OVAL document
	ovalDoc, err := oval.ParseBytes(data)
	if err != nil {
		t.Fatalf("Failed to parse OVAL document: %v", err)
	}

	// Verify generator info
	t.Logf("Generator Product: %s", ovalDoc.Generator.ProductName)
	t.Logf("Generator Version: %s", ovalDoc.Generator.ProductVersion)
	t.Logf("Generator Timestamp: %s", ovalDoc.Generator.Timestamp)

	if ovalDoc.Generator.ProductName != "Azure Linux OVAL Definition Generator" {
		t.Errorf("Unexpected product name: %s", ovalDoc.Generator.ProductName)
	}

	// Verify definitions were parsed
	if ovalDoc.Definitions == nil {
		t.Fatal("Definitions is nil")
	}

	numDefs := len(ovalDoc.Definitions.Definition)
	t.Logf("Number of definitions: %d", numDefs)

	if numDefs == 0 {
		t.Fatal("No definitions found")
	}

	// Check first definition
	firstDef := ovalDoc.Definitions.Definition[0]
	t.Logf("First definition ID: %s", firstDef.ID)
	t.Logf("First definition class: %s", firstDef.Class)
	t.Logf("First definition title: %s", firstDef.Metadata.Title)
	t.Logf("First definition description: %s", firstDef.Metadata.Description)

	if firstDef.Class != "vulnerability" {
		t.Errorf("Expected class 'vulnerability', got %s", firstDef.Class)
	}

	// Check affected
	if len(firstDef.Metadata.Affected) == 0 {
		t.Error("No affected platforms found")
	} else {
		affected := firstDef.Metadata.Affected[0]
		t.Logf("Affected family: %s", affected.Family)
		t.Logf("Affected platforms: %v", affected.Platform)
	}

	// Check references (CVE)
	if len(firstDef.Metadata.Reference) == 0 {
		t.Error("No references found")
	} else {
		ref := firstDef.Metadata.Reference[0]
		t.Logf("Reference source: %s", ref.Source)
		t.Logf("Reference ID: %s", ref.RefID)
		t.Logf("Reference URL: %s", ref.RefURL)
	}

	// Check criteria
	if firstDef.Criteria == nil {
		t.Error("Criteria is nil")
	} else {
		t.Logf("Criteria operator: %s", firstDef.Criteria.Operator)
		if len(firstDef.Criteria.Criterion) > 0 {
			t.Logf("First criterion test_ref: %s", firstDef.Criteria.Criterion[0].TestRef)
			t.Logf("First criterion comment: %s", firstDef.Criteria.Criterion[0].Comment)
		}
	}

	// Count vulnerability classes
	vulnCount := 0
	for _, def := range ovalDoc.Definitions.Definition {
		if def.Class == "vulnerability" {
			vulnCount++
		}
	}
	t.Logf("Vulnerability definitions: %d", vulnCount)

	// Verify tests were parsed (if present)
	if ovalDoc.Tests != nil {
		t.Logf("Number of generic tests: %d", len(ovalDoc.Tests.Test))
		t.Logf("Number of RPMInfo tests: %d", len(ovalDoc.Tests.RPMInfoTest))
	}

	// Verify objects were parsed (if present)
	if ovalDoc.Objects != nil {
		t.Logf("Number of generic objects: %d", len(ovalDoc.Objects.Object))
		t.Logf("Number of RPMInfo objects: %d", len(ovalDoc.Objects.RPMInfoObject))
	}

	// Verify states were parsed (if present)
	if ovalDoc.States != nil {
		t.Logf("Number of generic states: %d", len(ovalDoc.States.State))
		t.Logf("Number of RPMInfo states: %d", len(ovalDoc.States.RPMInfoState))

		// Check if we can access the first RPMInfo state's EVR
		if len(ovalDoc.States.RPMInfoState) > 0 {
			firstState := ovalDoc.States.RPMInfoState[0]
			t.Logf("First RPMInfo state ID: %s", firstState.ID)
			if firstState.EVR != nil {
				t.Logf("First RPMInfo state EVR: %s (operation: %s)", firstState.EVR.Value, firstState.EVR.Operation)
			}
		}
	}
}
