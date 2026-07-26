# CloudChain

An attack-path-aware Cloud Security Posture Management (CSPM) tool for AWS.

Most free CSPM tools (Prowler, ScoutSuite) report misconfigurations as a flat
list: "bucket X is public," "user Y has no MFA," each scored independently
with a static severity label. Real breaches happen through **chains** of
misconfigurations, not single ones. CloudChain scans an AWS account, then
builds a resource graph and asks: is there a path from something an attacker
can reach on the internet, all the way to `AdministratorAccess`? If so, that
chain is reported as a single critical narrative finding instead of being
buried across a dozen unrelated rows.

## What makes it different

**1. Attack-path chaining.** A public S3 bucket containing a leaked
credentials file, whose identity holds `iam:PassRole` + `lambda:CreateFunction`,
which can pass into a role with `AdministratorAccess` -- that's not three
unrelated findings, it's one attack path, and CloudChain reports it as such
with a plain-English narrative.

**2. Contextual risk scoring, not static severity labels.** Every CSPM
assigns a fixed severity per check. CloudChain instead scores each finding by
`base_severity x internet_facing x sensitive x on_attack_path`, so a finding
that's proven to sit on a path to full account takeover ranks far above the
same issue type in isolation (see `app/risk/scoring.py`).

**3. Drift detection across scans.** Every scan is persisted to SQLite.
Re-running a scan shows "3 new findings, 1 resolved" instead of only ever
showing a single point-in-time snapshot -- neither Prowler nor ScoutSuite do
this out of the box.

**4. Content-aware S3 scanning.** Beyond bucket-level ACL/policy checks,
CloudChain inspects object *keys* (not contents -- it never downloads
objects) inside public buckets for credential-like naming patterns
(`credentials.csv`, `.pem`, `.env`, `id_rsa`, ...), which is what feeds the
graph engine a real entry point.

## Architecture

```
CloudChain/
  backend/
    app/
    sources.py         # AWSDataSource interface + DemoAWSDataSource + RealAWSDataSource (boto3)
    demo/mock_aws.py    # seeded synthetic AWS account with an intentional escalation chain
    scanners/           # S3, IAM, Security Group checks -> Finding objects
    graph/              # networkx-based attack-path graph engine
    risk/               # contextual risk scoring
    storage/            # SQLite snapshot persistence + drift diffing
    report/             # assembles the final JSON report
      pipeline.py       # scan -> graph -> risk -> persist -> drift, one code path
      jobs.py           # background scan jobs + credential lifecycle
      main.py           # FastAPI app serving the React frontend
      cli.py            # run scans from the terminal, no server needed
    tests/              # pytest suite: scanners, graph, risk scoring, drift
  frontend/
    src/
      components/
        Aurora/          # React Bits WebGL aurora background (always on)
        CircularText/    # React Bits spinning circular text
        LoadingScreen/   # splash screen combining the two
        CardNav/         # React Bits animated top bar
        TopNav/          # wrapper: wires CardNav links to app routes
        VariableProximity/ # React Bits proximity-reactive variable font
        Wordmark/        # the CloudChain wordmark built on VariableProximity
        ModeSelect/      # choose demo account vs real AWS account
        AwsConnect/      # IAM access key form (validated via STS)
        ScanProgress/    # live stage-by-stage scan progress
        Dashboard/       # results: severity chart, attack paths, findings, drift
        ScanHistory/     # past scans, backed by /api/scans
        About/           # how it works / risk scoring / attack paths
      api/client.js      # fetch wrappers + scan job polling
      App.jsx            # view state machine driving the flow above
```

Scanners are written against the `AWSDataSource` interface and never know
whether they're talking to demo data or a live account -- swapping
`--mode demo` for `--mode real` changes nothing else in the pipeline.

## Demo mode

No AWS account required. `app/demo/mock_aws.py` seeds a small synthetic
account containing:

- `public-uploads-bucket` -- public, contains a "leaked" credentials file
  for IAM user `svc-deploy-bot`
- `svc-deploy-bot` -- no MFA, holds `iam:PassRole` + Lambda create/invoke,
  can pass into `LambdaExecutionAdminRole`
- `LambdaExecutionAdminRole` -- has `AdministratorAccess` attached
- A few "noise" resources (a clean locked-down bucket, a properly scoped
  internal security group, an MFA-enabled analyst user) so the risk engine
  has something to rank *below* the chained findings

This reproduces a real, well-known AWS privilege escalation primitive end
to end, so you always have something concrete to demo/screenshot even
without cloud infrastructure.

## Setup

Open the `CloudChain` folder (this one, not `backend/`) as your project root in
VS Code, then run the backend and frontend in two separate terminals.

### 1. Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate      # macOS / Linux
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

In VS Code, press Ctrl+Shift+P -> "Python: Select Interpreter" and pick the one
inside `backend/venv` so import warnings resolve.

Commands are written as `python -m <tool>` rather than calling `uvicorn.exe` /
`pytest.exe` directly: Windows Smart App Control blocks the unsigned launcher
shims pip generates in `venv\Scripts\`, and going through `python -m` avoids
them entirely.

### 2. Frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the printed http://localhost:5173 URL. The backend must stay running in the
first terminal, otherwise the app shows a "couldn't reach the backend" screen.

### Run a scan from the CLI (no server needed)

```bash
cd backend
python -m app.cli scan --mode demo          # pretty-printed report
python -m app.cli scan --mode demo --json   # raw JSON
python -m app.cli history --mode demo       # list past scans
```

Run it twice in a row and the second run's report will show
`Drift: New: 0  Resolved: 0  Unchanged: N`.

### Run against a real AWS account

Real scanning uses whatever AWS credentials are already configured
(`aws configure`, environment variables, or an instance role):

```bash
python -m app.cli scan --mode real
```

The account needs read-only permissions for S3, IAM, and EC2 (the `SecurityAudit`
managed policy covers it). Missing permissions degrade gracefully with a warning
instead of crashing the scan.

### API endpoints

| Method | Path                          | Description                             |
|--------|-------------------------------|-----------------------------------------|
| POST   | `/api/scan/start`             | Start a background scan, returns job id  |
| GET    | `/api/scan/status/{job_id}`   | Live stage progress, then the report     |
| POST   | `/api/aws/validate`           | Verify AWS keys via STS GetCallerIdentity|
| POST   | `/api/scan?mode=demo`         | Synchronous scan (CLI/scripting path)    |
| GET    | `/api/scans?mode=demo`        | List past scans                          |
| GET    | `/api/scans/{scan_id}`        | Full raw scan result (incl. graph)       |
| GET    | `/api/scans/{scan_id}/report` | Report view of a specific past scan      |
| GET    | `/api/report/latest?mode=demo`| Report for the most recent scan          |

`GET /api/scans/{scan_id}` includes the full `graph` object (`nodes`/`edges`) for
rendering the attack-path graph in the frontend.

### Frontend layers

| z  | Layer             | When           |
|----|-------------------|----------------|
| 0  | Aurora background | always         |
| 2  | Page content      | after loading  |
| 3  | LoadingScreen     | during loading |
| 99 | CardNav top bar   | after loading  |

### Top navigation

`CardNav` ships as plain `<a href>` links and a CTA button with no click
handlers, so rather than editing it, `TopNav` wraps it and uses event
delegation: it intercepts clicks inside the nav, reads the `#route` off the
anchor, and calls the app router. Same approach for the CTA button.
`CardNav.jsx` is unmodified from React Bits.

Routes: `#new-scan`, `#history`, `#latest`, `#demo`, `#aws`, `#about`,
`#about-scoring`, `#about-paths`.

`Scan history` and `Latest report` read the `/api/scans` and
`/api/report/latest` endpoints, so they show real stored snapshots rather than
placeholder data -- opening one loads that scan's full report.

The `CloudChain` wordmark uses `VariableProximity` with the Roboto Flex
variable font, so letter weight responds to cursor proximity.

### Application flow

```
splash (health check)
    |
    v
mode select ----> demo account -----------------+
    |                                            |
    +---------> AWS account -> credential form ->+
                                                 |
                                                 v
                                    staged scan progress
                                                 |
                                                 v
                                     results dashboard
```

The scan runs on a backend worker thread; the browser polls
`/api/scan/status/{job_id}` and renders the scanner's real position in the
pipeline (7 stages, from connection through graph correlation to drift diff).
Demo scans pause ~0.55s per stage -- defined as `DEMO_STAGE_DELAY_SECONDS` in
`app/jobs.py` -- purely so the progress UI is readable, since a seeded scan
otherwise finishes in milliseconds. Real scans use no artificial delay and are
paced by actual AWS API latency.

## Credential handling

Scanning a real account requires **IAM access keys**, not AWS console
credentials. CloudChain never asks for an AWS email or password -- no tool
legitimately needs those, and anything that requests them should be treated as
phishing.

Recommended setup: create a dedicated IAM user, attach the AWS-managed
`SecurityAudit` policy (read-only, covers S3/IAM/EC2), and generate an access
key for it.

Submitted keys are:

* validated up front with STS `GetCallerIdentity`, so bad keys fail fast with
  a clear message instead of producing an empty report,
* held in memory for the duration of a single scan and then dropped,
* never written to the SQLite snapshot database or any file,
* never logged, and never included in the job status payload returned to the
  browser (there is a test asserting this: `test_public_state_never_leaks_credentials`).

Only the resulting findings are persisted. `app/jobs.py` is the single
security-sensitive file here.

### Run the tests

```bash
cd backend
python -m pytest tests/ -v
```

26 tests covering scanner logic, attack-path graph construction, risk
scoring ordering, drift detection across scans, and the background job runner
(including an assertion that credentials never leak into API responses).

## Known limitations (worth mentioning if asked in an interview)

- Real-mode credential-leak correlation is intentionally limited: CloudChain
  never downloads object contents, only inspects key names, so it can flag
  *that* a bucket exposes credential-like files but can't automatically
  prove *whose* credentials without an external mapping (a secrets-scanning
  pipeline, for example). Demo mode uses a ground-truth hint to make the
  full chain reproducible without one.
- `get_policy_statements` for real accounts currently resolves AWS-managed
  policies by name; customer-managed and inline policies would need ARN
  resolution added for full parity (noted directly in `sources.py`).
- Coverage is S3 + IAM + EC2 security groups. Extending to RDS, Lambda, and
  CloudTrail-based drift context would be natural next steps.
