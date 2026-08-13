# HPB Lint

A deterministic WordPress and Gutenberg QA linter built for [HowProsBet](https://howprosbet.com/).

HPB Lint checks mechanical publishing rules that can be evaluated reliably by code. It was created to catch repeatable implementation errors in a live WordPress publishing workflow without pretending that subjective editorial or visual quality can be linted.

Current version: **0.2.5**

## What it checks

HPB Lint includes checks for:

* WordPress Gutenberg block structure
* unbalanced custom HTML
* executable scripts and local style blocks in content
* duplicate IDs
* responsive table requirements
* internal link normalization and unknown targets
* site-role and silo-link requirements
* basic accessibility issues
* inline SVG requirements
* CSS namespace and scope violations
* legacy CSS classes
* selected deterministic editorial rules
* WordPress WXR exports
* Screaming Frog inventory coverage

Findings are classified as `ERROR`, `WARN`, or `INFO`.

The guiding principle is simple: if a rule cannot be determined reliably by code, it should remain a human QA decision rather than become a noisy pseudo-lint.

## Project scope

HPB Lint is an open-source release of the internal QA tool used by HowProsBet.

It is **project-specific**, not a general-purpose drop-in WordPress linter. Several rules, namespaces and exceptions reflect the architecture and editorial policies of HowProsBet.

The source can be adapted for other publishing projects by changing the configuration and, where necessary, the project-specific rules in the Python code.

## Requirements

Install Python and then install the dependencies:

```bash
pip install -r requirements.txt
```

External Python dependencies:

```text
lxml
tinycss2
```

HPB Lint performs no network requests.

## Configuration

The repository includes:

```text
hpb_lint_config.example.json
```

Copy it to:

```text
hpb_lint_config.json
```

Then adapt the values to the site and publishing rules you want to lint.

The production HowProsBet configuration is intentionally not included in this repository.

## Basic usage

Show the installed version:

```bash
python hpb_lint.py --version
```

### Lint WordPress or Gutenberg HTML

```bash
python hpb_lint.py html article.html --config hpb_lint_config.json
```

A canonical URL can be supplied for URL-specific checks:

```bash
python hpb_lint.py html article.html \
  --config hpb_lint_config.json \
  --url https://example.com/example-page/
```

An inventory and role mapping can also be supplied for internal-link and role-aware checks:

```bash
python hpb_lint.py html article.html \
  --config hpb_lint_config.json \
  --inventory intern_html.csv \
  --roles roles.json
```

### Lint Additional CSS

```bash
python hpb_lint.py css additional.css --config hpb_lint_config.json
```

An earlier CSS file can be supplied as a baseline for diff-aware rules:

```bash
python hpb_lint.py css additional.css \
  --config hpb_lint_config.json \
  --baseline-css previous.css
```

### Lint a WordPress WXR export

```bash
python hpb_lint.py wxr wordpress-export.xml \
  --config hpb_lint_config.json
```

For a sitewide run with inventory and role context:

```bash
python hpb_lint.py wxr wordpress-export.xml \
  --config hpb_lint_config.json \
  --inventory intern_html.csv \
  --roles roles.json
```

A previous HPB JSON report can be used as a baseline:

```bash
python hpb_lint.py wxr wordpress-export.xml \
  --config hpb_lint_config.json \
  --inventory intern_html.csv \
  --roles roles.json \
  --baseline previous-report.json
```

This allows existing warnings to be separated from newly introduced or resolved warnings.

### Audit crawl and role coverage

```bash
python hpb_lint.py crawl intern_html.csv \
  --config hpb_lint_config.json \
  --roles roles.json
```

## How HowProsBet uses AUTO mode

Version 0.2.5 includes a zero-argument mode for the internal HowProsBet workflow.

When the required production files are stored next to `hpb_lint.py`, running:

```bash
python hpb_lint.py
```

automatically discovers:

```text
hpb_lint_config.json
hpb_roles.json
a valid WordPress WXR .xml export
an intern_html inventory CSV
an hpb_baseline_GREEN*.json report
```

For replaceable inputs such as the WXR export, inventory and Green baseline, the newest valid matching file is selected.

The production configuration, role mapping, site export, crawl inventory and baseline are not included in this public repository.

## Safe link fixes

HPB Lint can optionally write corrected copies for a limited set of mechanical internal-link issues.

For individual HTML:

```bash
python hpb_lint.py html article.html \
  --config hpb_lint_config.json \
  --fix-out fixed.html
```

For WXR runs:

```bash
python hpb_lint.py wxr wordpress-export.xml \
  --config hpb_lint_config.json \
  --fix-links-dir fixed-pages
```

These outputs are deliberately limited to the explicitly supported internal-link normalization rules. Editorial text is not automatically rewritten.

## Design philosophy

HPB Lint deliberately separates deterministic enforcement from human QA.

Code is appropriate for questions such as:

* Is this Gutenberg block properly closed?
* Does this table have the required responsive structure?
* Is this internal URL malformed?
* Is a forbidden legacy CSS class present?
* Does this SVG have the required accessibility attributes?

Code is not appropriate for questions such as:

* Is this visual useful?
* Is the explanation too complicated?
* Does the page make the right editorial argument?
* Is the design aesthetically good?
* Does the article genuinely help the reader?

Those remain human editorial and visual decisions.

## Status

HPB Lint v0.2.5 is the current production version used by HowProsBet.

The project is published primarily as a transparent example of the tooling behind the site's publishing and QA workflow.

## License

MIT License.
