//
// Copyright (c) Jeff Mendoza <jlm@jlm.name>
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// SPDX-License-Identifier: MIT
//

package main

import (
	"bytes"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jeffmendoza/ovaltoosv/ovaltoosv"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed osv-schema.json
var schemaFS embed.FS

// ValidationError represents a schema validation error
type ValidationError struct {
	Err error
}

func (e *ValidationError) Error() string {
	return e.Err.Error()
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}

func main() {
	inputFile := flag.String("i", "", "input file (default: stdin)")
	flag.Parse()

	// Check for required output directory positional argument
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Usage: ovaltoosv [-i input_file] <output_directory>")
		os.Exit(1)
	}
	outputDir := flag.Arg(0)

	var reader io.ReadCloser
	var err error

	// Setup input
	if *inputFile != "" {
		fmt.Fprintf(os.Stderr, "Reading from file: %s\n", *inputFile)
		reader, err = os.Open(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening input file: %v\n", err)
			os.Exit(1)
		}
		defer reader.Close()
	} else {
		fmt.Fprintln(os.Stderr, "Reading from stdin...")
		reader = os.Stdin
	}

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Writing to directory: %s\n", outputDir)

	// Run conversion
	if err := convert(reader, outputDir); err != nil {
		var valErr *ValidationError
		if errors.As(err, &valErr) {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}

func convert(r io.Reader, outputDir string) error {
	input, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	converter := ovaltoosv.NewConverter()
	if err := converter.ParseOVAL(string(input)); err != nil {
		return fmt.Errorf("parsing OVAL: %w", err)
	}

	if err := converter.ConvertToOSV(); err != nil {
		return fmt.Errorf("converting to OSV: %w", err)
	}

	output, err := converter.GetJSON()
	if err != nil {
		return fmt.Errorf("getting JSON: %w", err)
	}

	// Write each vulnerability as a separate JSON file
	var validationErr error
	for id, jsonBytes := range output {
		outputPath := filepath.Join(outputDir, id+".json")
		if err := os.WriteFile(outputPath, jsonBytes, 0644); err != nil {
			return fmt.Errorf("writing output for %s: %w", id, err)
		}

		// Validate each vulnerability against OSV schema (non-fatal)
		if err := validateOSV(jsonBytes); err != nil {
			validationErr = &ValidationError{Err: fmt.Errorf("validating OSV output for %s: %w", id, err)}
		}
	}

	return validationErr
}

func validateOSV(data []byte) error {
	schemaData, err := schemaFS.Open("osv-schema.json")
	if err != nil {
		return fmt.Errorf("opening embedded schema: %w", err)
	}
	defer schemaData.Close()

	schema, err := jsonschema.UnmarshalJSON(schemaData)
	if err != nil {
		return fmt.Errorf("parsing schema: %w", err)
	}

	c := jsonschema.NewCompiler()
	if err := c.AddResource("osv-schema.json", schema); err != nil {
		return fmt.Errorf("adding schema resource: %w", err)
	}

	sch, err := c.Compile("osv-schema.json")
	if err != nil {
		return fmt.Errorf("compiling schema: %w", err)
	}

	inst, err := jsonschema.UnmarshalJSON(io.NopCloser(io.Reader(bytes.NewReader(data))))
	if err != nil {
		return fmt.Errorf("parsing JSON output: %w", err)
	}

	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}

	return nil
}
