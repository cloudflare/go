// +build ignore

// Autogenerates wrappers from templates to prevent too much duplicated code
// between the code for different modes.
package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
	"text/template"
)

type Instance struct {
	Bits int
}

func (m Instance) Pkg() string {
	return strings.ToLower(m.Name())
}

func (m Instance) Name() string {
	return fmt.Sprintf("SIKEp%d", m.Bits)
}

func (m Instance) Field() string {
	return fmt.Sprintf("Fp%d", m.Bits)
}

var (
	Instances = []Instance{
		{Bits: 434},
		{Bits: 503},
		{Bits: 751},
	}
	TemplateWarning = "// Code generated from"
)

func main() {
	generatePackageFiles()
}

// Generates instance/sike.go from templates/pkg.templ.go
func generatePackageFiles() {
	tl, err := template.ParseFiles("templates/pkg.templ.go")
	if err != nil {
		panic(err)
	}

	for _, mode := range Instances {
		buf := new(bytes.Buffer)
		err := tl.Execute(buf, mode)
		if err != nil {
			panic(err)
		}

		res := string(buf.Bytes())
		offset := strings.Index(res, TemplateWarning)
		if offset == -1 {
			panic("Missing template warning in pkg.templ.go")
		}
		err = ioutil.WriteFile(mode.Pkg()+"/sike.go", []byte(res[offset:]), 0644)
		if err != nil {
			panic(err)
		}
	}
}
