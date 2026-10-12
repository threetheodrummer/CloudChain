#!/usr/bin/env bash
# CloudChain IAM evaluation testbed.
#
#   ./experiments/testbed.sh up      create the test users and roles
#   ./experiments/testbed.sh stale   "remediate" two cases, for the stale-path experiment
#   ./experiments/testbed.sh down    delete everything this script created
#
# Uses the cloudgoat-admin profile (override with ADMIN_PROFILE=...).
# Everything is IAM only: no buckets, functions or instances, so it costs
# nothing and works under an SCP that denies S3, Lambda and EC2.
# Every resource name starts with cc-eval- so `down` can't touch anything else.
# No access keys are created: CloudChain only needs to read the policies.
set -euo pipefail

P="${ADMIN_PROFILE:-cloudgoat-admin}"
aws_() { aws --profile "$P" "$@"; }
ACCOUNT="$(aws_ sts get-caller-identity --query Account --output text)"

LAMBDA_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

policy() {  # policy "<action json list>" "<resource>"
  printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":%s,"Resource":"%s"}]}' "$1" "$2"
}

# name | inline policy document | expected outcome (for the ground-truth table)
CASES=(
  "cc-eval-attach|$(policy '["iam:AttachUserPolicy"]' '*')|escalation route, CONFIRMED"
  "cc-eval-policyver|$(policy '["iam:CreatePolicyVersion"]' '*')|escalation route, CONFIRMED"
  "cc-eval-putpolicy|$(policy '["iam:PutUserPolicy"]' '*')|escalation route, CONFIRMED"
  "cc-eval-addgroup|$(policy '["iam:AddUserToGroup"]' '*')|escalation route, CONFIRMED"
  "cc-eval-passrole-lambda|$(printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::%s:role/cc-eval-admin-role"},{"Effect":"Allow","Action":["lambda:CreateFunction","lambda:InvokeFunction"],"Resource":"*"}]}' "$ACCOUNT")|path found statically, REFUTED by SCP (Lambda denied)"
  "cc-eval-wildcard-pass|$(policy '["iam:Pass*","lambda:Create*"]' '*')|path found via wildcard match, REFUTED by SCP"
  "cc-eval-passrole-scoped|$(printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::%s:role/cc-eval-harmless-role"},{"Effect":"Allow","Action":"lambda:CreateFunction","Resource":"*"}]}' "$ACCOUNT")|NEGATIVE: no path (can only pass a harmless role)"
  "cc-eval-readonly|$(policy '["iam:Get*","iam:List*"]' '*')|NEGATIVE: no escalation finding"
  "cc-eval-s3only|$(policy '["s3:*"]' '*')|NEGATIVE: no escalation (s3:* is not admin)"
)

up() {
  echo "Creating roles in account $ACCOUNT ..."
  aws_ iam create-role --role-name cc-eval-admin-role --assume-role-policy-document "$LAMBDA_TRUST" >/dev/null
  aws_ iam attach-role-policy --role-name cc-eval-admin-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
  aws_ iam create-role --role-name cc-eval-harmless-role --assume-role-policy-document "$LAMBDA_TRUST" >/dev/null

  for c in "${CASES[@]}"; do
    IFS='|' read -r name doc expect <<<"$c"
    aws_ iam create-user --user-name "$name" >/dev/null
    aws_ iam put-user-policy --user-name "$name" --policy-name cc-eval-policy --policy-document "$doc"
    printf '  %-26s expected: %s\n' "$name" "$expect"
  done
  echo "Waiting 20s for IAM to propagate ..."
  sleep 20
  echo "Done. Now run the CloudChain scan from Terminal C."
}

stale() {
  # Remediate two confirmed cases. Re-validating the earlier scan should now
  # return REFUTED for exactly these two routes and nothing else.
  for name in cc-eval-attach cc-eval-putpolicy; do
    aws_ iam delete-user-policy --user-name "$name" --policy-name cc-eval-policy
    echo "  removed escalation permission from $name"
  done
  echo "Waiting 20s for IAM to propagate ..."
  sleep 20
  echo "Now run validate (NOT a new scan) from Terminal C."
}

down() {
  for c in "${CASES[@]}"; do
    IFS='|' read -r name _ _ <<<"$c"
    aws_ iam delete-user-policy --user-name "$name" --policy-name cc-eval-policy 2>/dev/null || true
    aws_ iam delete-user --user-name "$name" 2>/dev/null && echo "  deleted $name" || true
  done
  aws_ iam detach-role-policy --role-name cc-eval-admin-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null || true
  for r in cc-eval-admin-role cc-eval-harmless-role; do
    aws_ iam delete-role --role-name "$r" 2>/dev/null && echo "  deleted $r" || true
  done
}

case "${1:-}" in
  up) up ;;
  stale) stale ;;
  down) down ;;
  *) echo "usage: $0 up|stale|down"; exit 1 ;;
esac
