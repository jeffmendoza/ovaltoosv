//
// Copyright (c) Jeff Mendoza <jlm@jlm.name>
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// SPDX-License-Identifier: MIT
//

package oval

import (
	"encoding/xml"
)

// Namespaces used in OVAL documents
const (
	OvalCommonNS      = "http://oval.mitre.org/XMLSchema/oval-common-5"
	OvalDefinitionsNS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
	LinuxDefinitionsNS = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
)

// OvalDefinitions represents the root OVAL definitions document
// Based on oval-definitions-schema.xsd
type OvalDefinitions struct {
	XMLName     xml.Name     `xml:"oval_definitions"`
	Generator   Generator    `xml:"generator"`
	Definitions *Definitions `xml:"definitions"`
	Tests       *Tests       `xml:"tests"`
	Objects     *Objects     `xml:"objects"`
	States      *States      `xml:"states"`
	Variables   *Variables   `xml:"variables"`
}

// Generator contains metadata about who generated the OVAL document
// Based on oval-common-schema.xsd GeneratorType
type Generator struct {
	ProductName    string          `xml:"product_name,omitempty"`
	ProductVersion string          `xml:"product_version,omitempty"`
	SchemaVersion  []SchemaVersion `xml:"schema_version"`
	Timestamp      string          `xml:"timestamp"` // Format: yyyy-mm-ddThh:mm:ss
}

// SchemaVersion represents the OVAL schema version with optional platform
type SchemaVersion struct {
	Value    string `xml:",chardata"`
	Platform string `xml:"platform,attr,omitempty"`
}

// Definitions is a container for Definition elements
type Definitions struct {
	Definition []Definition `xml:"definition"`
}

// Definition represents a single OVAL definition (vulnerability, patch, etc.)
// Based on oval-definitions-schema.xsd DefinitionType
type Definition struct {
	ID         string    `xml:"id,attr"`
	Version    int       `xml:"version,attr"`
	Class      string    `xml:"class,attr"`      // vulnerability, patch, inventory, compliance, miscellaneous
	Deprecated bool      `xml:"deprecated,attr"` // optional, default false
	Metadata   Metadata  `xml:"metadata"`
	Notes      *Notes    `xml:"notes,omitempty"`
	Criteria   *Criteria `xml:"criteria,omitempty"`
}

// Metadata contains descriptive information about the definition
// Based on oval-definitions-schema.xsd MetadataType
type Metadata struct {
	Title       string      `xml:"title"`
	Affected    []Affected  `xml:"affected,omitempty"`
	Reference   []Reference `xml:"reference,omitempty"`
	Description string      `xml:"description"`
	// Vendor-specific metadata extensions (xsd:any)
	Patchable    string `xml:"patchable,omitempty"`
	AdvisoryDate string `xml:"advisory_date,omitempty"`
	AdvisoryID   string `xml:"advisory_id,omitempty"`
	Severity     string `xml:"severity,omitempty"`
}

// Affected describes the system(s) for which the definition has been written
// Based on oval-definitions-schema.xsd AffectedType
type Affected struct {
	Family   string   `xml:"family,attr"` // windows, unix, ios, macos, etc.
	Platform []string `xml:"platform,omitempty"`
	Product  []string `xml:"product,omitempty"`
}

// Reference links the OVAL Definition to an external reference (e.g., CVE)
// Based on oval-definitions-schema.xsd ReferenceType
type Reference struct {
	Source string `xml:"source,attr"`
	RefID  string `xml:"ref_id,attr"`
	RefURL string `xml:"ref_url,attr,omitempty"`
}

// Notes contains additional notes about a definition or test
type Notes struct {
	Note []string `xml:"note"`
}

// Criteria describes a container for sub-criteria, criterion, or extend_definition
// Based on oval-definitions-schema.xsd CriteriaType
type Criteria struct {
	Operator           string             `xml:"operator,attr,omitempty"` // AND, OR, ONE, XOR (default: AND)
	Negate             bool               `xml:"negate,attr,omitempty"`
	Comment            string             `xml:"comment,attr,omitempty"`
	ApplicabilityCheck bool               `xml:"applicability_check,attr,omitempty"`
	Criteria           []Criteria         `xml:"criteria,omitempty"`
	Criterion          []Criterion        `xml:"criterion,omitempty"`
	ExtendDefinition   []ExtendDefinition `xml:"extend_definition,omitempty"`
}

// Criterion identifies a specific test to be included in the criteria
// Based on oval-definitions-schema.xsd CriterionType
type Criterion struct {
	TestRef            string `xml:"test_ref,attr"`
	Negate             bool   `xml:"negate,attr,omitempty"`
	Comment            string `xml:"comment,attr,omitempty"`
	ApplicabilityCheck bool   `xml:"applicability_check,attr,omitempty"`
}

// ExtendDefinition allows existing definitions to be extended
// Based on oval-definitions-schema.xsd ExtendDefinitionType
type ExtendDefinition struct {
	DefinitionRef      string `xml:"definition_ref,attr"`
	Negate             bool   `xml:"negate,attr,omitempty"`
	Comment            string `xml:"comment,attr,omitempty"`
	ApplicabilityCheck bool   `xml:"applicability_check,attr,omitempty"`
}

// Tests is a container for Test elements
type Tests struct {
	RPMInfoTest []RPMInfoTest `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux rpminfo_test"`
	Test        []Test        `xml:",any"`
}

// Test represents an abstract OVAL test (extended by component schemas)
// Based on oval-definitions-schema.xsd TestType
type Test struct {
	XMLName        xml.Name   `xml:""`
	ID             string     `xml:"id,attr"`
	Version        int        `xml:"version,attr"`
	CheckExistence string     `xml:"check_existence,attr,omitempty"` // default: at_least_one_exists
	Check          string     `xml:"check,attr"`
	StateOperator  string     `xml:"state_operator,attr,omitempty"` // default: AND
	Comment        string     `xml:"comment,attr"`
	Deprecated     bool       `xml:"deprecated,attr,omitempty"`
	Object         *ObjectRef `xml:"object,omitempty"`
	State          []StateRef `xml:"state,omitempty"`
}

// RPMInfoTest represents a Linux RPM info test
// Based on linux-definitions-schema.xsd rpminfo_test
type RPMInfoTest struct {
	XMLName        xml.Name   `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux rpminfo_test"`
	ID             string     `xml:"id,attr"`
	Version        int        `xml:"version,attr"`
	CheckExistence string     `xml:"check_existence,attr,omitempty"`
	Check          string     `xml:"check,attr"`
	StateOperator  string     `xml:"state_operator,attr,omitempty"`
	Comment        string     `xml:"comment,attr"`
	Deprecated     bool       `xml:"deprecated,attr,omitempty"`
	Object         *ObjectRef `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux object,omitempty"`
	State          []StateRef `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux state,omitempty"`
}

// ObjectRef references an OVAL object
type ObjectRef struct {
	ObjectRef string `xml:"object_ref,attr"`
}

// StateRef references an OVAL state
type StateRef struct {
	StateRef string `xml:"state_ref,attr"`
}

// Objects is a container for Object elements
type Objects struct {
	RPMInfoObject []RPMInfoObject `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux rpminfo_object"`
	// Generic fallback for other object types
	Object []Object `xml:",any"`
}

// Object represents an abstract OVAL object (extended by component schemas)
// Based on oval-definitions-schema.xsd ObjectType
type Object struct {
	XMLName    xml.Name `xml:""`
	ID         string   `xml:"id,attr"`
	Version    int      `xml:"version,attr"`
	Comment    string   `xml:"comment,attr,omitempty"`
	Deprecated bool     `xml:"deprecated,attr,omitempty"`
}

// RPMInfoObject represents a Linux RPM info object
// Based on linux-definitions-schema.xsd rpminfo_object
type RPMInfoObject struct {
	XMLName    xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux rpminfo_object"`
	ID         string   `xml:"id,attr"`
	Version    int      `xml:"version,attr"`
	Comment    string   `xml:"comment,attr,omitempty"`
	Deprecated bool     `xml:"deprecated,attr,omitempty"`
	Name       string   `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux name"` // Package name to check
}

// States is a container for State elements
type States struct {
	RPMInfoState []RPMInfoState `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux rpminfo_state"`
	// Generic fallback for other state types
	State []State `xml:",any"`
}

// State represents an abstract OVAL state (extended by component schemas)
// Based on oval-definitions-schema.xsd StateType
type State struct {
	XMLName    xml.Name `xml:""`
	ID         string   `xml:"id,attr"`
	Version    int      `xml:"version,attr"`
	Operator   string   `xml:"operator,attr,omitempty"` // default: AND
	Comment    string   `xml:"comment,attr,omitempty"`
	Deprecated bool     `xml:"deprecated,attr,omitempty"`
}

// RPMInfoState represents a Linux RPM info state
// Based on linux-definitions-schema.xsd rpminfo_state
type RPMInfoState struct {
	XMLName    xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux rpminfo_state"`
	ID         string   `xml:"id,attr"`
	Version    int      `xml:"version,attr"`
	Operator   string   `xml:"operator,attr,omitempty"`
	Comment    string   `xml:"comment,attr,omitempty"`
	Deprecated bool     `xml:"deprecated,attr,omitempty"`
	// RPM-specific fields
	Name     *EntityStateString `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux name,omitempty"`
	Arch     *EntityStateString `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux arch,omitempty"`
	Epoch    *EntityStateString `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux epoch,omitempty"`
	Release  *EntityStateString `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux release,omitempty"`
	EVR      *EntityStateEVR    `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux evr,omitempty"` // Combined epoch:version-release
	SigKeyID *EntityStateString `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux signature_keyid,omitempty"`
}

// EntityStateString represents a string entity state with operation attribute
type EntityStateString struct {
	Value     string `xml:",chardata"`
	Datatype  string `xml:"datatype,attr,omitempty"`
	Operation string `xml:"operation,attr,omitempty"` // equals, not equal, pattern match, etc.
}

// EntityStateEVR represents an EVR (epoch:version-release) entity state
// Based on oval-definitions-schema.xsd EntityStateEVRStringType
type EntityStateEVR struct {
	Value     string `xml:",chardata"`          // e.g., "0:2.16.1-10.azl3"
	Datatype  string `xml:"datatype,attr,omitempty"` // typically "evr_string"
	Operation string `xml:"operation,attr,omitempty"` // e.g., "less than"
}

// Variables is a container for Variable elements
type Variables struct {
	// Variables can be constant_variable, external_variable, local_variable
	// Using raw XML for now as these are complex
	Variable []Variable `xml:",any"`
}

// Variable represents an abstract OVAL variable
type Variable struct {
	XMLName    xml.Name `xml:""`
	ID         string   `xml:"id,attr"`
	Version    int      `xml:"version,attr"`
	Datatype   string   `xml:"datatype,attr,omitempty"`
	Comment    string   `xml:"comment,attr,omitempty"`
	Deprecated bool     `xml:"deprecated,attr,omitempty"`
}

// Parse parses OVAL XML input and returns the OvalDefinitions struct
func Parse(input string) (*OvalDefinitions, error) {
	var oval OvalDefinitions
	err := xml.Unmarshal([]byte(input), &oval)
	if err != nil {
		return nil, err
	}
	return &oval, nil
}

// ParseBytes parses OVAL XML from bytes and returns the OvalDefinitions struct
func ParseBytes(input []byte) (*OvalDefinitions, error) {
	var oval OvalDefinitions
	err := xml.Unmarshal(input, &oval)
	if err != nil {
		return nil, err
	}
	return &oval, nil
}

// GetRPMInfoState returns an RPMInfoState by ID, or nil if not found
func (o *OvalDefinitions) GetRPMInfoState(id string) *RPMInfoState {
	if o.States == nil {
		return nil
	}
	for i := range o.States.RPMInfoState {
		if o.States.RPMInfoState[i].ID == id {
			return &o.States.RPMInfoState[i]
		}
	}
	return nil
}

// GetRPMInfoObject returns an RPMInfoObject by ID, or nil if not found
func (o *OvalDefinitions) GetRPMInfoObject(id string) *RPMInfoObject {
	if o.Objects == nil {
		return nil
	}
	for i := range o.Objects.RPMInfoObject {
		if o.Objects.RPMInfoObject[i].ID == id {
			return &o.Objects.RPMInfoObject[i]
		}
	}
	return nil
}

// GetRPMInfoTest returns an RPMInfoTest by ID, or nil if not found
func (o *OvalDefinitions) GetRPMInfoTest(id string) *RPMInfoTest {
	if o.Tests == nil {
		return nil
	}
	for i := range o.Tests.RPMInfoTest {
		if o.Tests.RPMInfoTest[i].ID == id {
			return &o.Tests.RPMInfoTest[i]
		}
	}
	return nil
}

// GetTest returns a Test by ID, or nil if not found
// This searches both the generic Test collection and the RPMInfoTest collection
func (o *OvalDefinitions) GetTest(id string) *Test {
	if o.Tests == nil {
		return nil
	}
	// First check generic tests
	for i := range o.Tests.Test {
		if o.Tests.Test[i].ID == id {
			return &o.Tests.Test[i]
		}
	}
	return nil
}
