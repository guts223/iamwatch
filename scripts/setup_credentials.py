#!/usr/bin/env python3
"""Create your AWS credentials file from the access-key CSV that AWS let you download.

    python scripts\\setup_credentials.py "C:\\Users\\you\\Downloads\\me-admin_accessKeys.csv"

It reads the two values from the CSV, writes ~/.aws/credentials and ~/.aws/config (region us-east-1),
then asks AWS "who am I?" and prints your 12-digit account number. It never prints the keys.
"""
import csv
import os
import shutil
import sys


def read_keys(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = [r for r in csv.reader(f) if any(c.strip() for c in r)]
    if not rows:
        sys.exit("The file is empty.")
    header = [c.strip().lower() for c in rows[0]]
    if "access key id" in header and "secret access key" in header and len(rows) > 1:
        i, j = header.index("access key id"), header.index("secret access key")
        return rows[1][i].strip(), rows[1][j].strip()
    if "password" in header or "console sign-in url" in header or "user name" in header:
        sys.exit("This CSV is the console LOGIN file (user name / password), not the access-key file.\n"
                 "In the AWS website: IAM -> Users -> your user -> Security credentials -> Create access key\n"
                 "-> choose 'Command Line Interface (CLI)' -> download the NEW .csv and use that one.")
    if len(rows[0]) >= 2 and len(rows) == 1:           # a bare 'id,secret' line without header
        return rows[0][0].strip(), rows[0][1].strip()
    sys.exit("Could not find the 'Access key ID' and 'Secret access key' columns. First line of the file was: %s"
             % ", ".join(rows[0][:3]))


def main():
    if len(sys.argv) != 2:
        sys.exit('Usage: python scripts\\setup_credentials.py "path\\to\\your_accessKeys.csv"')
    path = sys.argv[1].strip().strip('"')
    if not os.path.exists(path):
        sys.exit("File not found: %s\nTip: in File Explorer, right-click the CSV and choose 'Copy as path'." % path)
    key_id, secret = read_keys(path)
    problems = []
    if not (key_id.startswith(("AKIA", "ASIA")) and len(key_id) == 20):
        problems.append("the Access key ID should start with AKIA and be 20 characters (this one is %d)" % len(key_id))
    if len(secret) != 40:
        problems.append("the Secret access key should be 40 characters (this one is %d)" % len(secret))
    if problems:
        sys.exit("The values in the CSV look wrong: " + "; ".join(problems) + ".")
    aws_dir = os.path.join(os.path.expanduser("~"), ".aws")
    os.makedirs(aws_dir, exist_ok=True)
    cred, conf = os.path.join(aws_dir, "credentials"), os.path.join(aws_dir, "config")
    for p in (cred, conf):
        if os.path.exists(p):
            shutil.copy(p, p + ".backup")
            print("existing %s saved as %s.backup" % (os.path.basename(p), os.path.basename(p)))
    with open(cred, "w") as f:
        f.write("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n" % (key_id, secret))
    with open(conf, "w") as f:
        f.write("[default]\nregion = us-east-1\noutput = json\n")
    print("saved credentials to", cred)
    try:
        import boto3
        acct = boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]
        print("\nSUCCESS - your laptop is connected to AWS account %s" % acct)
    except ImportError:
        print("\nSaved. (boto3 is not installed yet - run: pip install -r requirements-dev.txt, then test again)")
    except Exception as e:                                  # noqa: BLE001
        print("\nSaved, but AWS did not accept the keys: %s" % str(e)[:300])
        print("Check that the key is still 'Active' in IAM -> Users -> Security credentials, then try again.")


if __name__ == "__main__":
    main()
