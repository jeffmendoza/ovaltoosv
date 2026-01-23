//
// Copyright (c) Jeff Mendoza <jlm@jlm.name>
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// SPDX-License-Identifier: MIT
//

// Package ovaltoosv converts OVAL vulnerability definitions to OSV format.
//
// # Installation
//
//	go get github.com/jeffmendoza/ovaltoosv/ovaltoosv
//
// # Usage
//
// Create a converter, parse OVAL XML, convert to OSV, and retrieve the results:
//
//	c := ovaltoosv.NewConverter()
//
//	err := c.ParseOVAL(ovalXMLContent)
//	if err != nil {
//	    // handle error
//	}
//
//	err = c.ConvertToOSV()
//	if err != nil {
//	    // handle error
//	}
//
//	// Get JSON output as map of ID -> JSON bytes
//	jsonOutput, err := c.GetJSON()
//	if err != nil {
//	    // handle error
//	}
//
//	for id, jsonBytes := range jsonOutput {
//	    // write each vulnerability to a file, etc.
//	}
//
//	// Or access vulnerabilities directly as OSV schema objects
//	vulns := c.GetVulnerabilities()
//	for id, vuln := range vulns {
//	    // work with osvschema.Vulnerability objects
//	}
package ovaltoosv
