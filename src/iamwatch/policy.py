"""IAM policy parsing and a deliberately simplified, over-approximating evaluator.

What this does:
  * parses policy documents (dict, JSON string, or URL-encoded JSON string)
  * matches Action / NotAction / Resource / NotResource with IAM wildcards (* and ?)
  * evaluates "can this principal do <action> on <resource>?" returning one of
        NONE         -> not allowed (no allow, or an explicit unconditional deny)
        CONDITIONAL  -> allowed only if some Condition holds (we do not evaluate conditions)
        FULL         -> allowed without conditions

Deliberate simplifications (state these as limitations in your paper):
  * Condition blocks are never evaluated.  An Allow with a Condition gives CONDITIONAL.
    A Deny with a Condition is ignored (we assume the attacker can satisfy / avoid it).
  * Service control policies, resource policies (other than role trust policies),
    session policies and cross-account access are out of scope.
"""
import json
import re
from urllib.parse import unquote

NONE, CONDITIONAL, FULL = 0, 1, 2

_regex_cache = {}


def _regex(pattern, ignore_case):
    key = (pattern, ignore_case)
    rx = _regex_cache.get(key)
    if rx is None:
        escaped = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
        rx = re.compile("^" + escaped + "$", re.IGNORECASE if ignore_case else 0)
        _regex_cache[key] = rx
    return rx


def as_list(x):
    if x is None:
        return []
    if isinstance(x, (list, tuple)):
        return list(x)
    return [x]


def load_doc(doc):
    """Return a policy document as a dict.  Accepts dict / JSON str / URL-encoded JSON str."""
    if doc is None:
        return {"Version": "2012-10-17", "Statement": []}
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, (bytes, bytearray)):
        doc = doc.decode("utf-8")
    text = doc.strip()
    if text.startswith("%7B") or text.startswith("%7b"):
        text = unquote(text)
    try:
        return json.loads(text)
    except ValueError:
        return json.loads(unquote(text))


def statements(doc):
    """Return the list of statement dicts of a policy document."""
    d = load_doc(doc)
    st = d.get("Statement", [])
    if isinstance(st, dict):
        st = [st]
    return [s for s in st if isinstance(s, dict)]


def action_matches(stmt, action):
    if "Action" in stmt:
        return any(_regex(p, True).match(action) for p in as_list(stmt["Action"]))
    if "NotAction" in stmt:
        return not any(_regex(p, True).match(action) for p in as_list(stmt["NotAction"]))
    return False


def resource_matches(stmt, resource):
    if "Resource" in stmt:
        return any(_regex(p, False).match(resource) for p in as_list(stmt["Resource"]))
    if "NotResource" in stmt:
        return not any(_regex(p, False).match(resource) for p in as_list(stmt["NotResource"]))
    return False


def evaluate(stmts, action, resource):
    """Evaluate a flat list of statements. Returns (explicitly_denied, level)."""
    level = NONE
    for s in stmts:
        if not action_matches(s, action) or not resource_matches(s, resource):
            continue
        effect = s.get("Effect")
        has_condition = bool(s.get("Condition"))
        if effect == "Deny":
            if not has_condition:
                return True, NONE
        elif effect == "Allow":
            level = max(level, CONDITIONAL if has_condition else FULL)
    return False, level


# "Admin-equivalent" = full access to a set of canary actions spanning IAM and
# several other services.  This is structural and avoids treating policies like
# PowerUserAccess (which uses NotAction to exclude iam:*) as administrator.
ADMIN_CANARIES = [
    ("iam:PutUserPolicy", "arn:aws:iam::{acct}:user/canary"),
    ("ec2:RunInstances", "arn:aws:ec2:us-east-1:{acct}:instance/i-0canary"),
    ("s3:DeleteBucket", "arn:aws:s3:::canary-bucket"),
    ("lambda:CreateFunction", "arn:aws:lambda:us-east-1:{acct}:function:canary"),
    ("dynamodb:DeleteTable", "arn:aws:dynamodb:us-east-1:{acct}:table/canary"),
]


def admin_level(stmts, acct, boundary=None):
    """Return NONE/CONDITIONAL/FULL for 'these statements grant administrator access'."""
    lvl = FULL
    for action, res in ADMIN_CANARIES:
        res = res.format(acct=acct)
        denied, l = evaluate(stmts, action, res)
        if denied or l == NONE:
            return NONE
        if boundary is not None:
            bd, bl = evaluate(boundary, action, res)
            if bd or bl == NONE:
                return NONE
            l = min(l, bl)
        lvl = min(lvl, l)
    return lvl


def doc_is_admin(doc, acct):
    return admin_level(statements(doc), acct) != NONE


def arn_is_aws_managed(arn):
    """True for AWS-managed policy ARNs (arn:aws:iam::aws:policy/...)."""
    parts = arn.split(":")
    return len(parts) > 4 and parts[4] == "aws"
