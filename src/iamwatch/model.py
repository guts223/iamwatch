"""IAM state: the raw facts the graph is derived from.

Node ids are strings:  "user:NAME", "role:NAME", "group:NAME"  and the virtual sink "ADMIN".
Everything here is JSON-serialisable so the whole state can live in one S3 object.
"""
import copy

from . import policy as P

ADMIN = "ADMIN"

BUILTIN_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    },
    "arn:aws:iam::aws:policy/IAMFullAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
    },
    "arn:aws:iam::aws:policy/PowerUserAccess": {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["iam:CreateServiceLinkedRole", "iam:DeleteServiceLinkedRole",
                                           "iam:ListRoles", "organizations:DescribeOrganization",
                                           "account:ListRegions"], "Resource": "*"},
        ],
    },
    "arn:aws:iam::aws:policy/ReadOnlyAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Action": ["*:Get*", "*:List*", "*:Describe*"], "Resource": "*"}],
    },
}


def node_id(kind, name):
    return "%s:%s" % (kind, name)


def kind_of(node):
    return node.split(":", 1)[0] if node != ADMIN else "admin"


def name_of(node):
    return node.split(":", 1)[1] if node != ADMIN else ADMIN


def arn_account(arn):
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 else ""


class IamState:
    def __init__(self, account_id="000000000000"):
        self.account_id = account_id
        self.nodes = {}       # node_id -> attribute dict
        self.policies = {}    # arn -> {"versions": {vid: doc}, "default": vid|None, "unknown": bool}
        self.profiles = {}    # instance profile name -> {"arn": ..., "roles": [role names]}
        self._rebuild_indexes()

    # ------------------------------------------------------------------ indexes
    def _rebuild_indexes(self):
        self.arn_index = {}    # arn -> node
        self.attachers = {}    # managed policy arn -> set(node)
        self.bounded = {}      # boundary policy arn -> set(node)
        self.members = {}      # group node -> set(user node)
        for n, a in self.nodes.items():
            self.arn_index[a["arn"]] = n
            for arn in a.get("managed", []):
                self.attachers.setdefault(arn, set()).add(n)
            if a.get("boundary"):
                self.bounded.setdefault(a["boundary"], set()).add(n)
            for g in a.get("groups", []):
                self.members.setdefault(node_id("group", g), set()).add(n)

    # ------------------------------------------------------------------ basic accessors
    def kind(self, node):
        return kind_of(node)

    def name(self, node):
        return name_of(node)

    def arn(self, node):
        return self.nodes[node]["arn"]

    def node_by_arn(self, arn):
        return self.arn_index.get(arn)

    def principals(self):
        """Nodes that can *act* (users and roles)."""
        return [n for n in self.nodes if not n.startswith("group:")]

    # ------------------------------------------------------------------ mutation helpers
    def add_principal(self, kind, name, arn, trust=None, boundary=None):
        n = node_id(kind, name)
        if n in self.nodes:
            return n
        attrs = {"kind": kind, "name": name, "arn": arn, "managed": [], "inline": {}, "boundary": boundary}
        if kind == "user":
            attrs["groups"] = []
        if kind == "role":
            attrs["trust"] = P.load_doc(trust) if trust is not None else {"Statement": []}
        self.nodes[n] = attrs
        self.arn_index[arn] = n
        if boundary:
            self.bounded.setdefault(boundary, set()).add(n)
        return n

    def remove_principal(self, node):
        a = self.nodes.pop(node, None)
        if a is None:
            return
        self.arn_index.pop(a["arn"], None)
        for arn in a.get("managed", []):
            self.attachers.get(arn, set()).discard(node)
        if a.get("boundary"):
            self.bounded.get(a["boundary"], set()).discard(node)
        for g in a.get("groups", []):
            self.members.get(node_id("group", g), set()).discard(node)
        if node.startswith("group:"):
            for u in list(self.members.get(node, set())):
                if u in self.nodes and name_of(node) in self.nodes[u].get("groups", []):
                    self.nodes[u]["groups"].remove(name_of(node))
            self.members.pop(node, None)
        if node.startswith("role:"):
            for prof in self.profiles.values():
                if name_of(node) in prof["roles"]:
                    prof["roles"].remove(name_of(node))

    def attach_policy(self, node, arn):
        a = self.nodes[node]
        if arn not in a["managed"]:
            a["managed"].append(arn)
        self.attachers.setdefault(arn, set()).add(node)

    def detach_policy(self, node, arn):
        a = self.nodes[node]
        if arn in a["managed"]:
            a["managed"].remove(arn)
        self.attachers.get(arn, set()).discard(node)

    def put_inline(self, node, pname, doc):
        self.nodes[node]["inline"][pname] = P.load_doc(doc)

    def delete_inline(self, node, pname):
        self.nodes[node]["inline"].pop(pname, None)

    def set_trust(self, node, doc):
        self.nodes[node]["trust"] = P.load_doc(doc)

    def set_boundary(self, node, arn):
        a = self.nodes[node]
        old = a.get("boundary")
        if old:
            self.bounded.get(old, set()).discard(node)
        a["boundary"] = arn
        if arn:
            self.bounded.setdefault(arn, set()).add(node)

    def add_member(self, user, group):
        gname = name_of(group)
        if gname not in self.nodes[user]["groups"]:
            self.nodes[user]["groups"].append(gname)
        self.members.setdefault(group, set()).add(user)

    def remove_member(self, user, group):
        gname = name_of(group)
        if gname in self.nodes[user]["groups"]:
            self.nodes[user]["groups"].remove(gname)
        self.members.get(group, set()).discard(user)

    def set_policy(self, arn, versions, default, unknown=False):
        self.policies[arn] = {
            "versions": {v: P.load_doc(d) for v, d in versions.items()},
            "default": default,
            "unknown": unknown,
        }

    def add_profile(self, name, arn):
        self.profiles.setdefault(name, {"arn": arn, "roles": []})

    def role_profiles(self, role_name):
        return [pn for pn, pv in self.profiles.items() if role_name in pv["roles"]]

    # ------------------------------------------------------------------ permission views
    def policy_statements(self, arn):
        pol = self.policies.get(arn)
        if not pol or not pol.get("default"):
            return []
        return P.statements(pol["versions"].get(pol["default"]))

    def _node_policy_statements(self, node):
        a = self.nodes[node]
        out = []
        for doc in a["inline"].values():
            out.extend(P.statements(doc))
        for arn in a["managed"]:
            out.extend(self.policy_statements(arn))
        return out

    def identity_statements(self, node):
        """All identity-policy statements that apply to a principal (user also inherits groups)."""
        out = self._node_policy_statements(node)
        if node.startswith("user:"):
            for g in self.nodes[node].get("groups", []):
                gn = node_id("group", g)
                if gn in self.nodes:
                    out.extend(self._node_policy_statements(gn))
        return out

    def boundary_statements(self, node):
        b = self.nodes[node].get("boundary")
        if not b:
            return None
        return self.policy_statements(b)

    def effective_policy_arns(self, node):
        a = self.nodes[node]
        arns = list(a["managed"])
        if node.startswith("user:"):
            for g in a.get("groups", []):
                gn = node_id("group", g)
                if gn in self.nodes:
                    arns.extend(self.nodes[gn]["managed"])
        return arns

    def policy_fanout(self, arn):
        """Nodes whose effective permissions depend on managed policy `arn`."""
        out = set()
        for n in self.attachers.get(arn, ()):
            if n in self.nodes:
                out.add(n)
                if n.startswith("group:"):
                    out |= {u for u in self.members.get(n, ()) if u in self.nodes}
        for n in self.bounded.get(arn, ()):
            if n in self.nodes:
                out.add(n)
        return out

    # ------------------------------------------------------------------ (de)serialisation
    def to_dict(self):
        return {"account_id": self.account_id, "nodes": self.nodes,
                "policies": self.policies, "profiles": self.profiles}

    @classmethod
    def from_dict(cls, d):
        s = cls(d.get("account_id", "000000000000"))
        s.nodes = copy.deepcopy(d["nodes"])
        s.policies = copy.deepcopy(d["policies"])
        s.profiles = copy.deepcopy(d.get("profiles", {}))
        s._rebuild_indexes()
        return s

    def clone(self):
        return IamState.from_dict(self.to_dict())


def ensure_builtin(state, arn):
    """Make sure well-known AWS managed policies are present. Returns True if known."""
    if arn in state.policies and not state.policies[arn].get("unknown"):
        return True
    doc = BUILTIN_POLICIES.get(arn)
    if doc is None:
        return False
    state.set_policy(arn, {"v1": doc}, "v1")
    return True


def state_from_authorization_details(details, account_id=None):
    """Build an IamState from the (paginator-merged) output of iam:GetAccountAuthorizationDetails."""
    if account_id is None:
        for key in ("UserDetailList", "RoleDetailList", "GroupDetailList"):
            for item in details.get(key, []):
                account_id = arn_account(item["Arn"])
                break
            if account_id:
                break
    st = IamState(account_id or "000000000000")

    def boundary_of(item):
        pb = item.get("PermissionsBoundary") or {}
        return pb.get("PermissionsBoundaryArn")

    for g in details.get("GroupDetailList", []):
        n = st.add_principal("group", g["GroupName"], g["Arn"])
        for ap in g.get("AttachedManagedPolicies", []):
            st.attach_policy(n, ap["PolicyArn"])
        for ip in g.get("GroupPolicyList", []):
            st.put_inline(n, ip["PolicyName"], ip["PolicyDocument"])
    for u in details.get("UserDetailList", []):
        n = st.add_principal("user", u["UserName"], u["Arn"], boundary=boundary_of(u))
        st.nodes[n]["groups"] = list(u.get("GroupList", []))
        for ap in u.get("AttachedManagedPolicies", []):
            st.attach_policy(n, ap["PolicyArn"])
        for ip in u.get("UserPolicyList", []):
            st.put_inline(n, ip["PolicyName"], ip["PolicyDocument"])
    for r in details.get("RoleDetailList", []):
        n = st.add_principal("role", r["RoleName"], r["Arn"],
                             trust=r.get("AssumeRolePolicyDocument"), boundary=boundary_of(r))
        for ap in r.get("AttachedManagedPolicies", []):
            st.attach_policy(n, ap["PolicyArn"])
        for ip in r.get("RolePolicyList", []):
            st.put_inline(n, ip["PolicyName"], ip["PolicyDocument"])
        for prof in r.get("InstanceProfileList", []):
            st.add_profile(prof["InstanceProfileName"], prof["Arn"])
            if r["RoleName"] not in st.profiles[prof["InstanceProfileName"]]["roles"]:
                st.profiles[prof["InstanceProfileName"]]["roles"].append(r["RoleName"])
    st._rebuild_indexes()
    for pol in details.get("Policies", []):
        arn = pol["Arn"]
        used = pol.get("AttachmentCount", 0) > 0 or pol.get("PermissionsBoundaryUsageCount", 0) > 0
        customer = arn_account(arn) != "aws"
        if not (used or customer):
            continue
        versions = {v["VersionId"]: v["Document"] for v in pol.get("PolicyVersionList", [])}
        st.set_policy(arn, versions, pol.get("DefaultVersionId"))
    return st
