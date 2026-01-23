//
// Copyright (c) Jeff Mendoza <jlm@jlm.name>
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// SPDX-License-Identifier: MIT
//

package ovaltoosv

import (
	"os"
	"testing"
)

func TestAzureLinuxConversion(t *testing.T) {
	data, err := os.ReadFile("../test/azurelinux-3.0-oval.xml")
	if err != nil {
		t.Fatalf("Error reading file: %v", err)
	}

	converter := NewConverter()
	if err := converter.ParseOVAL(string(data)); err != nil {
		t.Fatalf("Error parsing OVAL: %v", err)
	}

	if err := converter.ConvertToOSV(); err != nil {
		t.Fatalf("Error converting: %v", err)
	}

	output, err := converter.GetJSON()
	if err != nil {
		t.Fatalf("Error getting JSON: %v", err)
	}

	t.Logf("Converted %d vulnerabilities", len(output))
}
