package main

const tpl = `#### LMD (Linux Malware Detect)
- **Status:** {{ .Results.Status }}
{{- if .Results.ScanID }}
- **Scan ID:** ` + "`" + `{{ .Results.ScanID }}` + "`" + `
{{- end }}
{{- if .Results.Error }}
- **Error:** {{ .Results.Error }}
{{- end }}
{{- if .Results.Scanner }}
- **Scanner:** {{ .Results.Scanner.Version }} ({{ .Results.Scanner.Engine }}, {{ .Results.Scanner.HashType }}, sigs {{ .Results.Scanner.SigVersion }})
{{- end }}
{{- if .Results.TotalFiles }}
- **Files scanned:** {{ .Results.TotalFiles }}
{{- end }}
{{- if .Results.Hits }}
| Signature | File | Type | Hash |
|-----------|------|------|------|
{{- range .Results.Hits }}
| {{ .Signature }} | {{ .File }} | {{ .HitType }} | {{ .Hash }} |
{{- end }}
{{- else if eq .Results.Status "clean" }}
 - No threats detected
{{- end }}
`
