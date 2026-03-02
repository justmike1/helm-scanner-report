# helm-trivy-report
Scans all container images in a Helm chart for known vulnerabilities using Trivy and generates a consolidated PDF/HTML report, sorted by severity. Supports local charts, remote repos, custom registries, image exclusions, and configurable severity levels.

## Project Structure

```
├── .github/actions/trivy-report/   # Reusable GitHub composite action
│   └── action.yml
├── src/
│   ├── scan.py                     # Main vulnerability scanner
│   └── templates/
│       ├── html.tpl                # HTML report template (with links)
│       └── html-no-links.tpl       # HTML report template (without links)
├── requirements.txt                # Python dependencies
├── README.md
└── LICENSE
```

## Usage as a GitHub Action

Other repositories can use this as a reusable composite action:

```yaml
jobs:
  trivy-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan Helm chart for vulnerabilities
        uses: justmike1/helm-trivy-report/.github/actions/trivy-report@main
        with:
          repo: "oci://registry.example.com/my-chart"
          version: "1.0.0"               # optional
          registry: ""                    # optional – override image registry
          exclude-images: "postgresql"    # optional – comma-separated
          severity-levels: "HIGH,CRITICAL"# optional (default: LOW,MEDIUM,HIGH,CRITICAL)
          show-links: "false"             # optional (default: false)
          retries: "3"                    # optional (default: 3)
          log-level: "INFO"               # optional (default: INFO)
          upload-artifact: "true"         # optional (default: true)
          artifact-name: "trivy-report"   # optional (default: trivy-vulnerability-report)
          retention-days: "3"             # optional (default: 3)
```

The action will:
1. Install Trivy, Helm, and Python dependencies automatically
2. Pull the Helm chart and discover all container images
3. Scan each image with Trivy
4. Generate a consolidated report sorted by severity
5. Upload the report as a GitHub Actions artifact

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `repo` | **yes** | — | Helm chart repository/path to scan |
| `version` | no | `""` | Helm chart version |
| `registry` | no | `""` | Registry prefix for images |
| `exclude-images` | no | `""` | Comma-separated substrings to exclude |
| `severity-levels` | no | `LOW,MEDIUM,HIGH,CRITICAL` | Severity levels to include |
| `show-links` | no | `false` | Show vulnerability reference links |
| `retries` | no | `3` | Retry count for failed scans |
| `log-level` | no | `INFO` | Log level |
| `upload-artifact` | no | `true` | Upload report as artifact |
| `artifact-name` | no | `trivy-vulnerability-report` | Artifact name |
| `retention-days` | no | `3` | Number of days to retain the artifact |

### Outputs

| Output | Description |
|--------|-------------|
| `report-path` | Path to the generated report file |

## Local CLI Usage

```bash
pip install -r requirements.txt
python src/scan.py --repo oci://registry.example.com/my-chart --version 1.0.0
```

Run `python src/scan.py --help` for all available options.
