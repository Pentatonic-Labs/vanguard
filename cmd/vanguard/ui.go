// vanguard ui — a read-only local dashboard for the hardware inventory and the
// findings produced by both loops (reactive CVM and proactive red-team).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/Pentatonic-Labs/vanguard/findings"
	"github.com/Pentatonic-Labs/vanguard/inventory/dgx/drivers"
	"github.com/Pentatonic-Labs/vanguard/inventory/dgx/firmware"
	"github.com/Pentatonic-Labs/vanguard/inventory/dgx/ngc"
	"github.com/Pentatonic-Labs/vanguard/inventory/dgx/platform"
)

type gpuView struct {
	Name   string `json:"name"`
	VBIOS  string `json:"vbios"`
	Driver string `json:"driver"`
}

type inventoryView struct {
	Driver       string    `json:"driver"`
	CUDA         string    `json:"cuda"`
	CuDNN        string    `json:"cudnn"`
	GPUs         []gpuView `json:"gpus"`
	FirmwareDevs []string  `json:"firmware_deviations"`
	NGCImages    int       `json:"ngc_images"`
	Triton       string    `json:"triton"`
	SoC          string    `json:"soc"`
	Grace        bool      `json:"grace"`
	MIGMode      string    `json:"mig_mode"`
	DPUNICs      []string  `json:"dpu_nics"`
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

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vanguard</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; font: 15px/1.5 system-ui, -apple-system, sans-serif; background: #0d0d10; color: #e6e6ea; }
  header { padding: 20px 28px; border-bottom: 1px solid #232329; display: flex; align-items: baseline; gap: 12px; }
  header h1 { margin: 0; font-size: 20px; letter-spacing: .5px; }
  header span { color: #8b8b93; font-size: 13px; }
  main { padding: 24px 28px; max-width: 960px; margin: 0 auto; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 1px; color: #8b8b93; margin: 28px 0 12px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px; }
  .card { background: #15151a; border: 1px solid #232329; border-radius: 8px; padding: 12px 14px; }
  .card .k { font-size: 12px; color: #8b8b93; text-transform: uppercase; letter-spacing: .5px; }
  .card .v { font-size: 15px; margin-top: 2px; word-break: break-all; }
  .finding { background: #15151a; border: 1px solid #232329; border-left: 3px solid #666; border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; }
  .finding .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .sev { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .5px; padding: 2px 8px; border-radius: 20px; }
  .sev.critical { background: #3a1215; color: #ff6b6b; }
  .sev.high { background: #3a2412; color: #ffb066; }
  .sev.medium { background: #3a3212; color: #f5d64c; }
  .sev.low { background: #12301f; color: #5fdb9f; }
  .sev.info, .sev.unknown { background: #232329; color: #9ba1a6; }
  .finding .sum { font-weight: 600; }
  .meta { color: #8b8b93; font-size: 12px; }
  .repro { background: #0d0d10; border: 1px solid #232329; border-radius: 6px; padding: 8px 10px; font-family: ui-monospace, monospace; font-size: 12px; margin: 10px 0; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
  .empty { color: #8b8b93; padding: 8px 0; }
  .gpus { margin-top: 12px; }
  .gpu { font-family: ui-monospace, monospace; font-size: 13px; padding: 4px 0; border-bottom: 1px dashed #232329; }
</style>
</head>
<body>
<header><h1>Vanguard</h1><span>hardware inventory &amp; proven findings</span></header>
<main>
  <h2>Hardware inventory</h2>
  <div class="grid" id="inv"></div>
  <div class="gpus" id="gpus"></div>
  <h2>Findings</h2>
  <div id="findings"><div class="empty">loading…</div></div>
</main>
<script>
function el(tag, cls, text) {
  var n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
function card(k, v) {
  var c = el('div', 'card');
  c.appendChild(el('div', 'k', k));
  c.appendChild(el('div', 'v', v === '' || v === undefined || v === null ? '—' : String(v)));
  return c;
}
function renderInventory(inv) {
  var grid = document.getElementById('inv');
  grid.innerHTML = '';
  grid.appendChild(card('NVIDIA driver', inv.driver));
  grid.appendChild(card('CUDA', inv.cuda));
  grid.appendChild(card('cuDNN', inv.cudnn));
  grid.appendChild(card('SoC', inv.soc));
  grid.appendChild(card('Grace (GB10)', inv.grace ? 'yes' : 'no'));
  grid.appendChild(card('MIG mode', inv.mig_mode));
  grid.appendChild(card('DPU / ConnectX', (inv.dpu_nics || []).join(', ')));
  grid.appendChild(card('NGC images', inv.ngc_images));
  grid.appendChild(card('Triton', inv.triton));
  var gpus = document.getElementById('gpus');
  gpus.innerHTML = '';
  (inv.gpus || []).forEach(function(g) {
    gpus.appendChild(el('div', 'gpu', g.name + '  ·  VBIOS ' + g.vbios + '  ·  driver ' + g.driver));
  });
  (inv.firmware_deviations || []).forEach(function(d) {
    gpus.appendChild(el('div', 'gpu', '⚠ ' + d));
  });
}
function renderFindings(list) {
  var box = document.getElementById('findings');
  box.innerHTML = '';
  if (!list || !list.length) { box.appendChild(el('div', 'empty', 'No findings yet. Run "go run ./cmd/vanguard scan" or the red-team attacker.')); return; }
  list.forEach(function(f) {
    var n = el('div', 'finding');
    var sev = (f.vuln && f.vuln.severity) || 'info';
    var row = el('div', 'row');
    row.appendChild(el('span', 'sev ' + sev, sev));
    row.appendChild(el('span', 'sum', (f.vuln && f.vuln.summary) || f.id));
    n.appendChild(row);
    var meta = (f.source || '') + (f.target && f.target.ref ? '  ·  ' + f.target.ref : '');
    n.appendChild(el('div', 'meta', meta));
    if (f.proof && f.proof.repro) n.appendChild(el('div', 'repro', f.proof.repro));
    if (f.impact) n.appendChild(el('div', 'meta', 'Impact: ' + f.impact));
    if (f.fix && f.fix.suggestion) n.appendChild(el('div', 'meta', 'Fix: ' + f.fix.suggestion));
    box.appendChild(n);
  });
}
Promise.all([fetch('/api/inventory'), fetch('/api/findings')])
  .then(function(rs) { return Promise.all(rs.map(function(r) { return r.json(); })); })
  .then(function(d) { renderInventory(d[0]); renderFindings(d[1]); })
  .catch(function(e) { document.getElementById('findings').appendChild(el('div', 'empty', 'error: ' + e)); });
</script>
</body>
</html>`
