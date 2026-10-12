# IAM Vulnerable evaluation

Benchmark: Bishop Fox, IAM Vulnerable (https://github.com/BishopFox/iam-vulnerable),
free modules `privesc-paths` and `tool-testing`.

- `ground_truth.json`: one case per Terraform file, with the users, roles and
  policies it creates. `fp*` cases are non-exploitable by design; all others are
  exploitable.
- `policies.json`: the policy documents, converted from the Terraform files.
- `offline_static.csv`: CloudChain's static IAM scanner on those policy documents,
  before and after the policy-semantics changes (explicit Deny, NotAction,
  PassRole-to-service catalogue, resource-dependent primitives, AWS-managed
  policy rule). Trust-based cases (AssumeRole chain, sre, permissive trust) are
  not in this offline table because they need the account's trust policies.
- `score.py`: scores CloudChain, Prowler and PMapper on the live deployment.
- `results.csv`: written by `score.py`.
