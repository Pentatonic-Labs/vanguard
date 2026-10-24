// vanguard ui — a read-only local dashboard for the hardware inventory and the
// findings produced by both loops (reactive CVM and proactive red-team).
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/Pentatonic-Labs/vanguard/findings"
	"github.com/Pentatonic-Labs/vanguard/inventory"
	"github.com/Pentatonic-Labs/vanguard/inventory/dgx/drivers"
	"github.com/Pentatonic-Labs/vanguard/inventory/dgx/firmware"
	"github.com/Pentatonic-Labs/vanguard/inventory/dgx/ngc"
	"github.com/Pentatonic-Labs/vanguard/inventory/dgx/platform"
)

//go:embed dashboard.html
var dashboardHTML string

type gpuView struct {
	Name   string `json:"name"`
	VBIOS  string `json:"vbios"`
	Driver string `json:"driver"`
}

type inventoryView struct {
	Host          string    `json:"host"`
	OS            string    `json:"os"`
	Driver        string    `json:"driver"`
	CUDA          string    `json:"cuda"`
	CuDNN         string    `json:"cudnn"`
	GPUs          []gpuView `json:"gpus"`
	FirmwareDevs  []string  `json:"firmware_deviations"`
	NGCImages     int       `json:"ngc_images"`
	Triton        string    `json:"triton"`
	SoC           string    `json:"soc"`
	Grace         bool      `json:"grace"`
	MIGMode       string    `json:"mig_mode"`
	DPUNICs       []string  `json:"dpu_nics"`
}

func runUI(args []string) {
	addr := "127.0.0.1:8080"
	dataDir := findings.DefaultDataDir
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-addr":
			if i+1 < len(args) {
				i++
				addr = args[i]
			}
		case "-data-dir":
			if i+1 < len(args) {
				i++
				dataDir = args[i]
			}
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/inventory", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, collectInventory())
	})
	mux.HandleFunc("/api/findings", func(w http.ResponseWriter, r *http.Request) {
		list, _ := findings.Load(dataDir)
		writeJSON(w, list)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, dashboardHTML)
	})

	fmt.Printf("vanguard ui: http://%s  (findings: %s)\n", addr, dataDir)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "vanguard ui:", err)
		os.Exit(1)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func collectInventory() inventoryView {
	v := inventoryView{}
	if host, err := os.Hostname(); err == nil {
		v.Host = host
	}
	if id := inventory.DetectOSID(); id != "" {
		v.OS = id + " " + inventory.DetectOSVersion()
	}
	if report, err := drivers.Detect(); err == nil {
		v.Driver = report.Driver.Version
		if report.CUDA.Toolkit != "" {
			v.CUDA = report.CUDA.Toolkit
		} else {
			v.CUDA = report.CUDA.Runtime
		}
		v.CuDNN = report.CuDNN.Version
	}
	if infos, err := firmware.Collect(context.Background()); err == nil {
		for _, f := range infos {
			v.GPUs = append(v.GPUs, gpuView{Name: f.GPUName, VBIOS: f.VBIOSVersion, Driver: f.DriverVersion})
		}
		for _, d := range firmware.CheckBaseline(infos) {
			v.FirmwareDevs = append(v.FirmwareDevs, fmt.Sprintf("%s %s: have %q want %q", d.GPUName, d.Field, d.Have, d.Want))
		}
	}
	if images, err := ngc.Collect(); err == nil {
		v.NGCImages = len(images)
	}
	if tv, err := ngc.DetectTritonVersion(); err == nil {
		v.Triton = tv
	}
	p := platform.Collect()
	v.SoC = p.SoCModel
	v.Grace = p.IsGrace
	v.MIGMode = p.MIGMode
	v.DPUNICs = p.NICs
	return v
}
