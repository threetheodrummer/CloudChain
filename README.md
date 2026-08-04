# CloudChain

[![CI](https://github.com/threetheodrummer/CloudChain/actions/workflows/ci.yml/badge.svg)](https://github.com/threetheodrummer/CloudChain/actions/workflows/ci.yml)

An attack-path-aware Cloud Security Posture Management (CSPM) tool for AWS.

Most free CSPM tools (Prowler, ScoutSuite) report misconfigurations as a flat
list: "bucket X is public," "user Y has no MFA," each scored independently
with a static severity label. Real breaches happen through **chains** of
misconfigurations, not single ones. CloudChain scans an AWS organisation, then
builds a resource graph and asks: is there a path from something an attacker
can reach on the internet, all the way to `AdministratorAccess`? If so, that
chain is reported as a single critical narrative finding instead of being
buried across a dozen unrelated rows.

Then it does two things the commercial tools don't: it goes back to the account
and **proves** each hop of that chain with read-only API calls, and it shows
its arithmetic for every number it puts on screen.

## What makes it different

**1. Attack-path chaining.** A public S3 bucket containing a leaked
credentials file, whose identity holds `iam:PassRole` + `lambda:CreateFunction`,
which can pass into a role with `AdministratorAccess` — that's not three
unrelated findings, it's one attack path, and CloudChain reports it as such
with a plain-English narrative.

Two kinds of route are reported, kept deliberately separate. **Attack paths**
start at an internet entry point and can be walked by an unauthenticated
attacker. **Escalation routes** start at an ordinary IAM identity and open
only once that identity is compromised. Merging them would overstate the
second and understate the first, so they get separate sections, separate
scoring floors, and a latent primitive can never score as badly as an open
door.

**2. Validated paths, not asserted ones.** Wiz, Orca and Prisma Cloud all
derive attack paths from configuration analysis and present them as fact. The
path is a *model output*, not an observation, and security teams know it — a
large share of reported paths turn out to be blocked by an SCP, a permission
boundary, or a resource policy the analyser never read. CloudChain re-checks
every hop against the live account and returns the API calls behind each
verdict, including the `aws-cli` equivalent so a reviewer can reproduce it by
hand. Hops come back `CONFIRMED`, `REFUTED` (the path is stale — that finding
on your dashboard is already fixed), or `UNVERIFIABLE`.

It never performs the escalation. Verifying "this identity can pass an admin
role into a Lambda" means confirming the *grant* via `iam:GetPolicyVersion`,
not creating a function. A `CONFIRMED` verdict means *every precondition is
verifiable right now*, not *we ran it* — a weaker claim than exploitation and a
much stronger one than configuration inference. See
[Safety guarantees](#safety-guarantees).

**3. An explainable posture score.** Every CSPM puts a single number on a
dashboard and none will tell you how it was produced, so teams learn not to
trust it. CloudChain's 0–100 score decomposes into four independent dimensions,
each publishing its own formula and naming the exact findings behind it:

| Dimension | Max | Measures |
|---|---|---|
| Exposure | −25 | Internet-reachable findings, weighted by severity |
| Privilege | −25 | How over-permissioned the identity layer is |
| Reachability | −30 | Whether a confirmed route to admin exists, and its shape |
| Blast radius | −20 | Fraction of the graph reachable from exposed entry points |

Click any dimension in the UI and it expands into `raw × weight = points`
plus a table of contributing findings. A test asserts the headline number
always equals 100 minus the published deductions — if the dashboard ever lies
about its own arithmetic, CI fails.

A flat severity ladder ("−4 per HIGH") was the obvious alternative and is worse:
it makes the score a proxy for account size, and it moves by the same amount
whether the HIGH you fixed was a public bucket leaking credentials or an
unencrypted internal volume.

**4. Organisation-wide, not per-account.** In a real org the interesting chain
almost always crosses an account boundary — a workload account gets
compromised, and the damage happens because a role in shared services trusts it
too broadly. Neither account looks compromised on its own, so per-account
tooling cannot see it. CloudChain namespaces every graph node by account
(`111111111111/iam_user:svc-deploy-bot`), gives each account its own
`AdministratorAccess` sink, and models cross-account movement as
`sts:AssumeRole` against a role whose *trust policy* names an external
principal.

That mechanism is deliberately separate from `iam:PassRole`. PassRole is
same-account by construction — AWS will not let you pass a role that lives
elsewhere — so it can never cross a boundary. Collapsing the two would produce
chains that look plausible and cannot actually be walked, which is exactly the
failure that makes people stop trusting CSPM output. There's a test asserting
no boundary crossing ever uses a PassRole edge.

**5. Shift-left: the same engine, on a Terraform plan.** Finding an attack path
after it exists is useful; not merging it is better. `PlanDataSource`
implements the same `AWSDataSource` interface the live scanners read from, so
the scanners, graph engine and posture model run against `terraform show -json`
completely unchanged — there is no second analysis implementation to drift.

```bash
terraform plan -out=tfplan && terraform show -json tfplan > plan.json
python -m app.cli plan --file plan.json --account 111111111111
```

Exits `1` when the change introduces a new route to `AdministratorAccess`, `0`
otherwise. `--format markdown` emits a ready-to-post PR comment.

**6. Attribution — who changed this, and when.** Drift tells you a finding is
new. The question everyone asks next, and that no CSPM answers, is *who did
it*. CloudChain maps each issue code to the CloudTrail management events that
could have caused it and reports the actor, timestamp, source IP and user
agent:

> `PutBucketAcl` on `public-uploads-bucket` by `legacy-ci-user` from
> `203.0.113.47` on 24 Jul 2026 at 06:11 UTC.

This is inference, and it's labelled as such. CloudTrail records that a change
happened, not that it produced this exact finding state, so every result
carries a confidence: `EXACT` (one candidate event), `LIKELY` (several — the
most recent is shown and the rest returned alongside it), or `UNATTRIBUTED`.

`UNATTRIBUTED` is common and is not a failure. `LookupEvents` reads the 90-day
event history, not a trail's S3 archive, so older changes are genuinely
unanswerable this way. Saying "no event found" is correct; naming a plausible
culprit would not be.

**7. Contextual risk scoring, not static severity labels.** Every CSPM assigns
a fixed severity per check. CloudChain scores each finding by
`base_severity × internet_facing × sensitive × on_attack_path`, and every
finding row in the UI expands to show that multiplier chain — replacing a
severity label with a computed number is only an improvement if the number can
be questioned.

**8. Drift detection across scans.** Every scan is persisted to SQLite, so
re-running shows "3 new, 1 resolved" rather than only ever a point-in-time
snapshot. Fingerprints include the account id, because resource names are only
unique within an account.

**9. Content-aware S3 scanning.** Beyond bucket-level ACL/policy checks,
CloudChain inspects object *keys* — never contents, it does not call
`GetObject` — inside public buckets for credential-like naming patterns
(`credentials.csv`, `.pem`, `.env`, `id_rsa`, …), which is what feeds the graph
engine a real entry point.

## Architecture

```
CloudChain/
  backend/
    app/
      sources.py          # AWSDataSource interface + Demo + Real (boto3) implementations
      models.py           # Pydantic schemas shared by every layer
      pipeline.py         # analyse_sources(): scanners -> graph -> scoring, one code path
      jobs.py             # background scan jobs + credential lifecycle
      main.py             # FastAPI app
      cli.py              # scans and plan checks from the terminal, no server needed
      demo/mock_aws.py    # seeded synthetic AWS *organisation* (3 accounts)
      scanners/           # S3, IAM, security group checks -> Finding objects
      graph/              # networkx attack-path engine, account-namespaced
      scanners/policy.py  # wildcard-aware IAM action matching + escalation primitives
      risk/scoring.py     # per-finding contextual score + its derivation
      risk/posture.py     # 0-100 account posture, decomposed into four dimensions
      validation/         # re-check a reported path against the account, read-only
      attribution/        # CloudTrail: who made the change, and when
      terraform/          # plan parsing, plan-as-data-source, pre-deploy diff
      storage/            # SQLite snapshot persistence + drift diffing
      report/generator.py # assembles the final JSON report
      report/pdf.py       # renders that same report as a downloadable PDF
    Dockerfile
    tests/                # 194 tests; fixtures/ holds sample Terraform plans
  frontend/
    src/
      components/
        Landing/           # entry screen
        ModeSelect/        # demo account vs real AWS account
        AwsConnect/        # IAM access key form (validated via STS)
        ScanProgress/      # live stage-by-stage scan progress
        Dashboard/         # results: posture, paths, findings, drift
        RiskGauge/         # posture gauge + expandable dimension breakdown
        PathValidation/    # per-hop evidence trail with the API calls behind it
        Attribution/       # who changed what, with the CloudTrail record
        AttackGraph/       # SVG chain view, with account-boundary markers
        ScanHistory/       # past scans, backed by /api/scans
        About/             # how it works / risk scoring / attack paths
        Aurora, CircularText, CardNav, TopNav, VariableProximity,
        Wordmark, GlowPanel, BorderGlow, CursorGrid, LoadingScreen
      api/client.js          # fetch wrappers + scan job polling
      App.jsx                # view state machine
```

Scanners are written against `AWSDataSource` and never know whether they're
reading demo data, a live account, or a Terraform plan. That single abstraction
is what makes `--mode demo`, `--mode real` and `plan --file` the same pipeline.

## Demo mode

No AWS account required. `app/demo/mock_aws.py` seeds a synthetic organisation
of three accounts:

| Account | Name | Role in the story |
|---|---|---|
| `111111111111` | prod | The workload account, and where the foothold is |
| `222222222222` | shared-services | Hosts a deployment role that trusts prod and carries admin |
| `333333333333` | sandbox | Mostly clean, so the risk engine has something to rank below |

Two chains fall out of this, and the difference between them is the point:

**In-account (prod).** `public-uploads-bucket` is public and contains
`backup/credentials.csv` belonging to `svc-deploy-bot`, who has no MFA and holds
`iam:PassRole` + Lambda create/invoke into `LambdaExecutionAdminRole`, which
carries `AdministratorAccess`.

**Cross-account (prod → shared-services).** The same compromised identity is
named in the trust policy of `OrgDeploymentRole` in shared-services, which also
carries `AdministratorAccess`. `OrgDeploymentRole` looks entirely reasonable
inside its own account; `svc-deploy-bot` looks like an ordinary
over-permissioned service account inside prod. The pair is wide open.

The demo account scores **24/100, grade F**, with reachability the largest
single contributor. Both chains validate as `CONFIRMED` end to end.

## Quick start with Docker

```bash
docker compose up --build
```

Open http://localhost:8080. Demo mode needs no AWS credentials.

nginx serves the built frontend and proxies `/api` to the backend, so the
browser sees a single origin and CORS isn't involved. Scan snapshots live on a
named volume — without one, drift detection resets on every restart and quietly
stops being able to report anything.

## Setup (without Docker)

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

In VS Code, press Ctrl+Shift+P → "Python: Select Interpreter" and pick the one
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

### Check a Terraform plan before applying it

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json

cd backend
python -m app.cli plan --file plan.json --account 111111111111
python -m app.cli plan --file plan.json --format markdown   # PR comment
```

Only a **new route to admin** fails the build. New MEDIUMs print as `WARN` and
pass — a gate that fails on every new medium gets switched off within a
fortnight, and then it protects nothing.

Two sample plans live in `backend/tests/fixtures/` if you want to see both
verdicts without writing any Terraform.

### Run against a real AWS account

Real scanning uses whatever AWS credentials are already configured
(`aws configure`, environment variables, or an instance role):

```bash
python -m app.cli scan --mode real
```

The account needs read-only permissions for S3, IAM, and EC2 (the `SecurityAudit`
managed policy covers it). Missing permissions degrade gracefully with a warning
instead of crashing the scan.

[`docs/testing-against-real-aws.md`](docs/testing-against-real-aws.md) walks
through validating real mode against a free-tier account end to end — IAM setup,
cost safety, what a clean account should look like, and an optional seeded
escalation chain so there's something for the graph engine to find.

### API endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scan/start` | Start a background scan, returns job id |
| GET | `/api/scan/status/{job_id}` | Live stage progress, then the report |
| POST | `/api/aws/validate` | Verify AWS keys via STS `GetCallerIdentity` |
| POST | `/api/scan?mode=demo` | Synchronous scan (CLI/scripting path) |
| GET | `/api/scans?mode=demo` | List past scans |
| GET | `/api/scans/{scan_id}` | Full raw scan result (incl. graph) |
| GET | `/api/scans/{scan_id}/report` | Report view of a specific past scan |
| GET | `/api/scans/{scan_id}/report.pdf` | The same report as a downloadable PDF |
| POST | `/api/scans/{scan_id}/validate` | Re-check every attack path, read-only |
| POST | `/api/scans/{scan_id}/attribute` | Name the actor and API call behind each finding |
| POST | `/api/plan/analyze` | Analyse a Terraform plan and diff it against a scan |
| GET | `/api/report/latest?mode=demo` | Report for the most recent scan |

`GET /api/scans/{scan_id}` includes the full `graph` object (`nodes`/`edges`) for
rendering the attack-path graph in the frontend.

Validating or attributing a **real**-mode scan requires supplying credentials
again in the request body, because scan-time credentials are deliberately never
persisted.

## Suppressing known-benign roles

Every account has infrastructure that legitimately holds broad permissions —
CI runners, provisioning roles, lab harnesses. CloudChain will report them,
correctly, and drown the findings you can act on.

```bash
CLOUDCHAIN_BENIGN_ROLES="LabOrchestratorRole,ci-*,*-provisioner"
```

Matched roles are **downgraded to LOW and annotated**, never dropped. The
report states which rule fired and adds *"the finding is real; someone decided
it was acceptable."* A suppression you can't see in the output is
indistinguishable from a bug.

Role provenance is reported at three confidence levels, because they are not
equally trustworthy:

| Level | Basis | Forgeable? |
|---|---|---|
| `aws_service_linked` | path `/aws-service-role/` | No — IAM refuses to create roles there |
| `aws_named` | matches an AWS naming convention | **Yes** — names are chosen by whoever creates the role |
| `operator_allowlisted` | your config | Yes — it's a human judgement, by design |

That middle row is the one worth understanding. A role called
`AWSServiceRoleForEvil` at an ordinary path gets downgraded on the strength of
its name alone, and the report says so in as many words. Path-based
verification is the only part of this that constitutes proof.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request:

- **Backend tests** on Python 3.10 and 3.13 — the supported floor, and a
  version new enough to surface deprecations early.
- **Frontend build** with `npm ci` against the lockfile.
- **Self-check** — a real demo scan on a clean runner, plus both Terraform
  fixtures through the gate. The dangerous plan *must* exit non-zero; if that
  step ever goes green, the shift-left check has silently stopped working,
  which is worse than not having one.

`.github/workflows/terraform-plan-check.yml` is a reusable workflow, so an
infrastructure repo can gate its pull requests without vendoring anything:

```yaml
jobs:
  cloudchain:
    uses: threetheodrummer/CloudChain/.github/workflows/terraform-plan-check.yml@main
    with:
      plan-file: plan.json
      account-id: "111111111111"
```

It posts the verdict as a PR comment and updates that comment in place on each
push rather than adding a new one, so a long-running pull request stays
readable. `fail-on-new-path: false` reports without blocking, which is a
sensible way to introduce the gate to a team already mid-flight.

## Safety guarantees

CloudChain audits accounts; it must never change one. That's enforced
structurally rather than by convention.

- **Validation is read-only by construction.** It is written against
  `AWSDataSource`, whose entire surface is reads, and `READ_ONLY_METHODS` in
  `app/validation/path_validator.py` allowlists the exact set of methods it may
  call.
  A test wraps the data source in a tripwire and **fails the build** if
  validation ever touches anything else.
- **No escalation is ever performed.** No role is assumed, no function created,
  no policy attached. Preconditions are verified; the attack is not run.
- **Object contents are never read.** The S3 checks confirm a bucket is public
  and that a credential-shaped key is *listable*. `GetObject` is never called —
  whether that file really contains live credentials is not something a scanner
  should determine by reading it.
- **Missing information never reads as a pass.** An `AccessDenied` or an
  unresolvable policy yields `UNVERIFIABLE`, never `CONFIRMED`. There's a test
  for this specifically, because it's the failure mode that would quietly turn
  the feature into a liar.

## Credential handling

Scanning a real account requires **IAM access keys**, not AWS console
credentials. CloudChain never asks for an AWS email or password — no tool
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

## Application flow

```
splash (health check)
    |
    v
mode select ----> demo organisation ------------+
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
Demo scans pause ~0.55s per stage — `DEMO_STAGE_DELAY_SECONDS` in
`app/jobs.py` — purely so the progress UI is readable, since a seeded scan
otherwise finishes in milliseconds. Real scans use no artificial delay and are
paced by actual AWS API latency.

## Run the tests

```bash
cd backend
python -m pytest tests/ -v
```

194 tests covering scanner logic, attack-path graph construction, cross-account
correlation, risk scoring, the posture engine's explainability contract,
path validation and its safety guarantees, CloudTrail attribution, Terraform
plan parity, escalation-route discovery, PDF export, drift detection, and the
background job runner.

A few are worth reading as documentation of intent:

| Test | Protects |
|---|---|
| `test_score_is_reconstructible_from_components` | The posture score always equals 100 minus its published deductions |
| `test_validation_only_calls_read_only_methods` | Validation can never mutate the audited account |
| `test_unresolvable_policies_are_unverifiable_not_confirmed` | Missing data never reads as a pass |
| `test_cross_account_hop_uses_assume_role_not_passrole` | No reported chain is unwalkable in real AWS |
| `test_a_partial_plan_does_not_claim_to_have_removed_the_rest` | A small PR can't claim credit for the whole account |
| `test_no_matching_event_is_unattributed_not_guessed` | Attribution never invents a culprit |
| `test_events_do_not_leak_between_accounts` | A resource name in one account can't match another's trail |
| `test_public_state_never_leaks_credentials` | Submitted keys never reach the browser |

## Known limitations

Worth being able to state plainly — most of these are deliberate.

- **Credential-leak correlation in real mode is limited by design.** CloudChain
  never downloads object contents, only inspects key names, so it can flag
  *that* a bucket exposes credential-like files but can't automatically prove
  *whose* credentials without an external mapping (a secrets-scanning pipeline,
  for example). Demo mode uses a ground-truth hint to make the full chain
  reproducible without one.
- **Real mode scans one account.** The graph is organisation-wide and the demo
  exercises three accounts, but scanning a live AWS Organization needs a
  management-account role and an `sts:AssumeRole` fan-out, which CloudChain
  doesn't attempt with a single submitted key pair.
- **Plan checking is silent on runtime facts.** A `terraform plan` cannot know
  whether a user enrolled MFA or how old an access key is, so those checks
  return the safe answer and stay quiet in CI rather than flagging every pull
  request for something the author can't fix from Terraform. The post-apply
  scan still covers them.
- **Coverage is S3 + IAM + EC2 security groups.** RDS, Lambda, KMS, NACLs,
  VPC flow logs, EBS snapshots and instance metadata are all out of scope —
  confirmed by pointing CloudChain at rooms built around each of them and
  correctly getting nothing back.
- **Explicit Deny, SCPs, permission boundaries and condition keys are not
  modelled.** All four can make a grant that looks live actually unusable, so a
  permission finding is a *claim* — which is precisely why the validation engine
  exists to re-check it rather than trusting the analysis.
- **Key age can't be tested in an ephemeral lab.** `IAM_STALE_ACCESS_KEY` needs
  a key older than 90 days. Training environments are provisioned minutes before
  you scan them, so the check correctly finds nothing there — a limitation of
  the test harness, not the scanner.
- **Attribution reaches back 90 days.** `LookupEvents` reads CloudTrail's event
  history, not a trail's S3 archive. Going further would mean querying the
  archive with Athena, which is a different (and much slower) shape of
  integration.
- **Attribution matches on resource name, not ARN.** CloudTrail's
  `ResourceName` lookup is name-based, so a resource renamed after the change
  won't match its own history.

## Roadmap

- A deployed demo instance so the tool can be tried without cloning it.
- Timeline view — reconstruct account posture at any past point, using the
  stored snapshots plus attribution.
- Broader coverage: RDS, Lambda, KMS, and multi-region scanning.
- Scanning a real AWS Organization via a management-account role and
  `sts:AssumeRole` fan-out, so real mode matches the org-wide graph model.
