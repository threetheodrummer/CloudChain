# Testing CloudChain against a real AWS account

Demo mode proves the analysis engine works. It doesn't prove `RealAWSDataSource`
works, because that code path — boto3 clients, pagination, `AccessDenied`
degradation, ARN parsing — never executes against seeded data.

This walks through validating real mode with an AWS free-tier account. Every
API call CloudChain makes is a read, and reads against a near-empty account
cost effectively nothing.

---

## 1. Create the account

Sign up at <https://aws.amazon.com/free>. You'll need a card for identity
verification; free-tier read operations won't charge it.

**Use a separate account from anything real.** Not your employer's, not one
holding personal data. If you later seed the deliberate misconfigurations in
step 6, you want them nowhere near anything that matters.

## 2. Secure the root user before anything else

Two things, both in the console under your account name → **Security
credentials**:

1. **Enable MFA on the root user.** Root has unrestricted access and cannot be
   scoped down. This is the single highest-value five minutes in AWS.
2. **Never create access keys for root.** If AWS offers, decline. Everything
   below uses a scoped IAM user instead.

## 3. Set a billing alarm

Billing console → **Budgets** → create a zero-spend or $1 budget with an email
alert. Nothing here should cost money, so an alert means something is running
that you didn't intend.

## 4. Create the scanning IAM user

IAM → **Users** → **Create user**.

- Name: `cloudchain-scanner`
- **Do not** grant console access — this identity only needs API access
- Permissions → **Attach policies directly** → search and attach
  **`SecurityAudit`** (AWS-managed, read-only, covers S3, IAM, EC2 and
  CloudTrail lookups)

Then open the user → **Security credentials** → **Create access key** →
choose **Third-party service** → create.

Copy both values now; the secret is shown exactly once.

> If you skip `SecurityAudit` and the scan returns an oddly empty report, that's
> the permission degradation working as designed — CloudChain logs a warning and
> continues rather than crashing. Check the backend logs.

## 5. Run the scan

In CloudChain, choose **AWS account**, paste the key id and secret, leave the
session token blank, pick **us-east-1**, and press **Validate and scan**.

**What to expect on a brand-new account:** almost nothing. A fresh account has
no buckets, no custom roles, no security groups beyond the default VPC. You
should see:

- STS validation succeeds and shows your account id
- The scan completes through all seven stages
- A handful of findings at most — likely `IAM_WEAK_PASSWORD_POLICY`, possibly
  an open default security group
- Posture near 100, grade A, **zero attack paths**

That is a **successful test**, not a broken one. It proves authentication,
enumeration, the graph engine and scoring all run against real AWS. It just
proves it against a clean account, which is the honest result.

To see the interesting behaviour you need something to find — step 6.

## 6. Optional: seed a deliberate attack chain

Only in the throwaway account from step 1.

This recreates the demo org's escalation chain with real resources, so you can
watch CloudChain discover a genuine route to `AdministratorAccess` in real mode.
It is the same thing intentionally-vulnerable training environments like
CloudGoat and flaws.cloud do, and it is how you actually verify a detection tool
detects.

**Rules, not suggestions:**

- Throwaway account only, never one with real data
- The "credentials" file contains **fake** text — never a real key
- Delete everything in step 7 the moment you're done
- Don't leave a public bucket sitting on the internet overnight

```bash
# Pick a globally unique bucket name
BUCKET="cloudchain-test-$(date +%s)"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

# --- a public bucket containing a credential-shaped file -----------------
aws s3api create-bucket --bucket "$BUCKET" --region us-east-1
aws s3api delete-public-access-block --bucket "$BUCKET"
aws s3api put-bucket-ownership-controls --bucket "$BUCKET" \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerPreferred}]'
aws s3api put-bucket-acl --bucket "$BUCKET" --acl public-read

echo "user,access_key,secret
NOT-REAL,AKIAEXAMPLENOTREAL01,this-is-fake-test-data-only" > credentials.csv
aws s3 cp credentials.csv "s3://$BUCKET/backup/credentials.csv"

# --- a role with AdministratorAccess a Lambda can assume -----------------
aws iam create-role --role-name CloudChainTestAdminRole \
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]
  }'
aws iam attach-role-policy --role-name CloudChainTestAdminRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# --- a user who can pass that role into new compute ----------------------
aws iam create-user --user-name cloudchain-test-deployer
aws iam put-user-policy --user-name cloudchain-test-deployer \
  --policy-name TestDeployPolicy \
  --policy-document "{
    \"Version\":\"2012-10-17\",
    \"Statement\":[
      {\"Effect\":\"Allow\",\"Action\":\"iam:PassRole\",\"Resource\":\"arn:aws:iam::${ACCOUNT}:role/CloudChainTestAdminRole\"},
      {\"Effect\":\"Allow\",\"Action\":[\"lambda:CreateFunction\",\"lambda:InvokeFunction\"],\"Resource\":\"*\"}
    ]
  }"

# --- a security group open to the internet -------------------------------
VPC=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true \
      --query 'Vpcs[0].VpcId' --output text)
SG=$(aws ec2 create-security-group --group-name cloudchain-test-sg \
     --description "CloudChain test - delete me" --vpc-id "$VPC" \
     --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id "$SG" \
  --protocol tcp --port 22 --cidr 0.0.0.0/0

echo "Seeded. Bucket: $BUCKET  SG: $SG"
```

Re-scan. You should now see the full chain: public bucket → deployer user →
admin role → `AdministratorAccess`, a posture score that drops sharply, and a
grade of F.

**One honest difference from demo mode.** Real mode won't wire the
bucket → user edge automatically, because CloudChain never reads object
*contents* — it can see a credential-shaped key name but cannot prove whose
credentials it holds. So you'll get the `PassRole` → admin half of the chain
and a separate critical finding on the bucket, rather than one continuous path.
That limitation is deliberate and documented in the README; seeing it in
practice is worth more than reading about it.

Attribution, on the other hand, should work: CloudTrail Event History is
enabled by default and free for 90 days, so "Who changed this" ought to name
your own scanner user and the calls you just made.

## 7. Tear it all down

```bash
aws s3 rm "s3://$BUCKET" --recursive
aws s3api delete-bucket --bucket "$BUCKET"

aws iam delete-user-policy --user-name cloudchain-test-deployer \
  --policy-name TestDeployPolicy
aws iam delete-user --user-name cloudchain-test-deployer

aws iam detach-role-policy --role-name CloudChainTestAdminRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-role --role-name CloudChainTestAdminRole

aws ec2 delete-security-group --group-id "$SG"

rm -f credentials.csv
```

Then delete the `cloudchain-scanner` access key in IAM, and check the Billing
console shows zero.

---

## What this does and doesn't prove

**Proves:** authentication, boto3 enumeration, pagination, the graph engine and
scoring all work against AWS's real API contract, in a real account.

**Doesn't prove:** behaviour at scale, or against partial permissions. A real
production account has thousands of resources and a scanning role that is
denied a dozen things. Those paths still have no coverage — which is what a
`moto` test suite would close, and is worth doing before claiming real mode is
production-ready.
