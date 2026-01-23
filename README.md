# OVAL to OSV Converter

A tool for converting [OVAL (Open Vulnerability and Assessment Language)](https://github.com/OVAL-Community/OVAL) definitions to [OSV (Open Source Vulnerability)](https://ossf.github.io/osv-schema/) format.

## Install

```sh
go install github.com/jeffmendoza/ovaltoosv@latest
```

Make sure `$GOBIN` is in your path.

- `$GOBIN` defaults to `$GOPATH/bin`
- `$GOPATH` defaults to `$HOME/go` on Unix and `%USERPROFILE%\go` on Windows

## Use

Example:
```sh
ovaltoosv -i oval-definitions.xml outputdir/
```

This will read `oval-definitions.xml` (or stdin if `-i` is not provided) and convert the OVAL vulnerability definitions to OSV format. Each vulnerability will be written as a separate JSON file in the output directory.

## Go Package

This functionality is also available as a Go package for use in your own projects. See the [package documentation](https://pkg.go.dev/github.com/jeffmendoza/ovaltoosv/ovaltoosv) for details.

## Thanks

This project uses:
- [OSV Schema Go bindings](https://github.com/ossf/osv-schema) for generating OSV-compliant output
- [packageurl-go](https://github.com/package-url/packageurl-go) for Package URL handling
- [jsonschema](https://github.com/santhosh-tekuri/jsonschema) for JSON schema validation

## License

MIT - See [LICENSE](LICENSE) for details.
