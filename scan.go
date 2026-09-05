package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/fatih/structs"
	"github.com/malice-plugins/pkgs/database"
	"github.com/malice-plugins/pkgs/database/elasticsearch"
	"github.com/malice-plugins/pkgs/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	name     = "lmd"
	category = "av"

	// maldetPath is the Linux Malware Detect CLI installed at build time.
	maldetPath = "maldet"
	// malwareDir is where the malice core stages the sample: /malware/<sha256>.
	malwareDir = "/malware"
)

var (
	// Version stores the plugin's version
	Version string
	// BuildTime stores the plugin's build time
	BuildTime string
	// es is the elasticsearch database object
	es elasticsearch.Database
)

// scanIDRe captures the SCANID from maldet's
// "scan report saved, to view run: maldet --report <SCANID>" line.
var scanIDRe = regexp.MustCompile(`maldet --report ([0-9]{6}-[0-9]{4}\.[0-9]+)`)

// errEmptyFileList is returned when maldet builds an empty file list (the
// sample is outside the scan scope, e.g. excluded by configuration). This is
// a "not applicable" outcome, reported as status "skipped".
var errEmptyFileList = errors.New("empty file list")

// Lmd json object
type Lmd struct {
	Results ResultsData `json:"lmd" structs:"lmd"`
}

// ResultsData is stored under plugins.av.lmd. It carries a found/status
// pair, a curated subset of the LMD JSON report, and a human-readable
// markdown summary.
type ResultsData struct {
	Found      bool         `json:"found" structs:"found"`
	Status     string       `json:"status" structs:"status"`
	ScanID     string       `json:"scan_id,omitempty" structs:"scan_id,omitempty"`
	Error      string       `json:"error,omitempty" structs:"error,omitempty"`
	Scanner    *ScannerInfo `json:"scanner,omitempty" structs:"scanner,omitempty"`
	TotalFiles int          `json:"total_files,omitempty" structs:"total_files,omitempty"`
	TotalHits  int          `json:"total_hits,omitempty" structs:"total_hits,omitempty"`
	Hits       []Hit        `json:"hits" structs:"hits"`
	MarkDown   string       `json:"markdown,omitempty" structs:"markdown,omitempty"`
}

// ScannerInfo mirrors the scanner block of the LMD JSON report.
type ScannerInfo struct {
	Version    string `json:"version" structs:"version"`
	Engine     string `json:"engine,omitempty" structs:"engine,omitempty"`
	HashType   string `json:"hash_type,omitempty" structs:"hash_type,omitempty"`
	SigVersion string `json:"sig_version,omitempty" structs:"sig_version,omitempty"`
}

// Hit is one matched signature (curated subset of an LMD hit record).
type Hit struct {
	Signature string `json:"signature" structs:"signature"`
	File      string `json:"file" structs:"file"`
	HitType   string `json:"hit_type,omitempty" structs:"hit_type,omitempty"`
	Hash      string `json:"hash,omitempty" structs:"hash,omitempty"`
	Size      *int64 `json:"size,omitempty" structs:"size,omitempty"`
}

// lmdReport is the envelope of `maldet --json-report <SCANID>` (schema 1.2).
// Pointer fields mirror LMD's null-emitting fields (jstr_or_null /
// jnum_or_null in the renderer).
type lmdReport struct {
	SchemaVersion string       `json:"schema_version"`
	Scanner       lmdScanner   `json:"scanner"`
	Host          lmdHost      `json:"host"`
	Reports       []lmdScan    `json:"reports"`
}

type lmdScanner struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Engine     string `json:"engine"`
	HashType   string `json:"hash_type"`
	SigVersion string `json:"sig_version"`
}

type lmdHost struct {
	Hostname string `json:"hostname"`
	HostID   string `json:"host_id"`
}

type lmdScan struct {
	ScanID            string   `json:"scan_id"`
	Type              string   `json:"type"`
	Path              string   `json:"path"`
	TotalFiles        *int     `json:"total_files"`
	TotalHits         *int     `json:"total_hits"`
	TotalCleaned      *int     `json:"total_cleaned"`
	TotalQuarantined  int      `json:"total_quarantined"`
	QuarantineEnabled bool     `json:"quarantine_enabled"`
	Hits              []lmdHit `json:"hits"`
}

type lmdHit struct {
	Index        int     `json:"index"`
	Signature    string  `json:"signature"`
	File         string  `json:"file"`
	HitType      string  `json:"hit_type"`
	HitTypeLabel string  `json:"hit_type_label"`
	Quarantined  bool    `json:"quarantined"`
	Hash         *string `json:"hash"`
	Size         *int64  `json:"size"`
	Owner        *string `json:"owner"`
	Group        *string `json:"group"`
	Mode         *string `json:"mode"`
	Mtime        *int64  `json:"mtime"`
}

func assert(err error) {
	if err != nil {
		log.WithFields(log.Fields{
			"plugin":   name,
			"category": category,
		}).Fatal(err)
	}
}

// runMaldet executes the maldet CLI and returns its combined stdout.
func runMaldet(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, maldetPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := stdout.String()
	if err != nil {
		// maldet logs progress to stderr; keep stdout as the payload.
		return out, errors.Wrapf(err, "maldet %s: %s", strings.Join(args, " "), strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// isMaldetHitExit reports whether err is maldet's "scan completed with
// >=1 hit" exit status. maldet's postrun() exits 2 when tot_hits >= 1
// (and 0 when clean), so a non-zero exit is NOT necessarily a failure.
func isMaldetHitExit(err error) bool {
	ee, ok := errors.Cause(err).(*exec.ExitError)
	return ok && ee.ExitCode() == 2
}

// scanFile runs `maldet -a <path>` and returns the SCANID of the completed
// scan. The scan and the subsequent --json-report query must share a single
// container run because LMD's session state does not persist. A maldet
// exit status of 2 means "hits found" (a successful scan), not an error.
func scanFile(ctx context.Context, path string) (string, error) {
	out, err := runMaldet(ctx, "-a", path)
	if err != nil && !isMaldetHitExit(err) {
		return "", errors.Wrapf(err, "failed to scan file: %s", path)
	}
	m := scanIDRe.FindStringSubmatch(out)
	if m == nil {
		if strings.Contains(out, "empty file list") {
			return "", errEmptyFileList
		}
		return "", errors.Errorf("no scan ID found in maldet output for %s: %s", path, strings.TrimSpace(out))
	}
	return m[1], nil
}

// fetchReport runs `maldet --json-report <scanID>` and returns the raw JSON.
func fetchReport(ctx context.Context, scanID string) (string, error) {
	out, err := runMaldet(ctx, "--json-report", scanID)
	if err != nil {
		return "", errors.Wrapf(err, "failed to fetch JSON report for scan %s", scanID)
	}
	return out, nil
}

// buildResults converts a parsed LMD report into the malice document shape.
func buildResults(rep lmdReport) ResultsData {
	res := ResultsData{Hits: []Hit{}}

	if len(rep.Reports) == 0 {
		res.Status = "clean"
		res.Found = false
		return res
	}

	scan := rep.Reports[0]
	res.ScanID = scan.ScanID
	res.Scanner = &ScannerInfo{
		Version:    rep.Scanner.Version,
		Engine:     rep.Scanner.Engine,
		HashType:   rep.Scanner.HashType,
		SigVersion: rep.Scanner.SigVersion,
	}
	if scan.TotalFiles != nil {
		res.TotalFiles = *scan.TotalFiles
	}
	if scan.TotalHits != nil {
		res.TotalHits = *scan.TotalHits
	}
	for _, h := range scan.Hits {
		hit := Hit{
			Signature: h.Signature,
			File:      h.File,
			HitType:   h.HitType,
		}
		if h.Hash != nil {
			hit.Hash = *h.Hash
		}
		if h.Size != nil {
			hit.Size = h.Size
		}
		res.Hits = append(res.Hits, hit)
	}

	if res.TotalHits > 0 {
		res.Found = true
		res.Status = "infected"
	} else {
		res.Found = false
		res.Status = "clean"
	}
	return res
}

// buildErrorResult builds a {found:false, status:"error"} document so a
// failed scan still leaves a written record.
func buildErrorResult(status, scanID, msg string) ResultsData {
	return ResultsData{
		Found:  false,
		Status: status,
		ScanID: scanID,
		Error:  msg,
		Hits:   []Hit{},
	}
}

func generateMarkDownTable(c Lmd) string {
	var tplOut bytes.Buffer
	t := template.Must(template.New("lmd").Parse(tpl))
	if err := t.Execute(&tplOut, c); err != nil {
		log.Println("executing template:", err)
	}
	return tplOut.String()
}

// store writes the results to ES. Returns an error only for ES-level
// failures (the caller turns those into a non-zero exit).
func store(results ResultsData, path string) error {
	if len(es.URL) == 0 {
		return nil
	}
	if err := es.Init(); err != nil {
		return errors.Wrap(err, "failed to initialize elasticsearch")
	}
	return es.StorePluginResults(database.PluginResults{
		ID:       utils.Getopt("MALICE_SCANID", utils.GetSHA256(path)),
		Name:     name,
		Category: category,
		Data:     structs.Map(results),
	})
}

func main() {
	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "lmd"
	app.Author = "rufftruffles"
	app.Email = "https://github.com/malice-plugins"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice LMD Plugin (rfxn/linux-malware-detect backend)"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.StringFlag{
			Name:        "elasticsearch",
			Value:       "",
			Usage:       "elasticsearch url for Malice to store results",
			EnvVar:      "MALICE_ELASTICSEARCH_URL",
			Destination: &es.URL,
		},
		cli.BoolFlag{
			Name:  "table, t",
			Usage: "output as Markdown table",
		},
		cli.IntFlag{
			Name:   "timeout",
			Value:  60,
			Usage:  "malice plugin timeout (in seconds)",
			EnvVar: "MALICE_TIMEOUT",
		},
	}
	app.ArgsUsage = "SHA256 of the file to scan (staged at /malware/<sha256>)"
	app.Action = func(c *cli.Context) error {
		if c.Bool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if !c.Args().Present() {
			return errors.New("please supply a sha256 to scan with LMD")
		}

		sha := c.Args().First()
		path := filepath.Join(malwareDir, sha)
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				// Non-applicable: sample not staged. Write a skipped doc.
				res := buildErrorResult("skipped", "", fmt.Sprintf("sample not found at %s", path))
				res.MarkDown = generateMarkDownTable(Lmd{Results: res})
				if err := store(res, path); err != nil {
					return errors.Wrapf(err, "failed to index malice/%s results", name)
				}
				fmt.Println(marshal(Lmd{Results: res}))
				return nil
			}
			return errors.Wrap(err, "failed to stat sample")
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Int("timeout"))*time.Second)
		defer cancel()

		var res ResultsData
		scanID, err := scanFile(ctx, path)
		if err != nil {
			if errors.Cause(err) == errEmptyFileList {
				res = buildErrorResult("skipped", "", "sample outside scan scope (empty file list)")
			} else {
				res = buildErrorResult("error", "", err.Error())
			}
		} else {
			raw, ferr := fetchReport(ctx, scanID)
			if ferr != nil {
				res = buildErrorResult("error", scanID, ferr.Error())
			} else {
				var rep lmdReport
				if jerr := json.Unmarshal([]byte(raw), &rep); jerr != nil {
					res = buildErrorResult("error", scanID, "failed to parse LMD JSON report: "+jerr.Error())
				} else {
					res = buildResults(rep)
				}
			}
		}
		res.MarkDown = generateMarkDownTable(Lmd{Results: res})

		if err := store(res, path); err != nil {
			return errors.Wrapf(err, "failed to index malice/%s results", name)
		}

		if c.Bool("table") {
			fmt.Println(res.MarkDown)
		} else {
			fmt.Println(marshal(Lmd{Results: res}))
		}
		return nil
	}

	err := app.Run(os.Args)
	assert(err)
}

func marshal(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
