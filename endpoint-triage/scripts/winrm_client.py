#!/usr/bin/env python3
"""Minimal WinRM (PowerShell remoting) client used by triage.sh.

Connects over HTTPS with certificate authentication (no password) to the listener that
Set-TriageAccess.ps1 creates on the endpoint, normally through a remote-support tool's TCP tunnel.

    winrm_client.py --cert C --key K [--host 127.0.0.1] [--port 5986] [--thumbprint T] COMMAND ...

Commands:
    info                      print the server certificate thumbprint, computer name, user and elevation
    push LOCAL_DIR REMOTE_DIR replace REMOTE_DIR with a copy of LOCAL_DIR
    run SCRIPT                run PowerShell SCRIPT and print its output
    pull REMOTE_DIR LOCAL_DIR copy REMOTE_DIR's contents into LOCAL_DIR

TLS is capped at 1.2: Windows asks for the client certificate after the handshake, which Python's
TLS stack does not do under TLS 1.3. The endpoint's server certificate is self-signed, so it is
checked by thumbprint (--thumbprint, printed by Set-TriageAccess.ps1) instead of by a CA.
"""
import os
import sys
import tempfile

# Must happen before ssl/requests are imported: OpenSSL reads this when it initialises.
_TLS12_CONF = tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False)
_TLS12_CONF.write(
    "openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n[ssl_sect]\n"
    "system_default = system_default_sect\n[system_default_sect]\nMaxProtocol = TLSv1.2\n"
)
_TLS12_CONF.close()
os.environ["OPENSSL_CONF"] = _TLS12_CONF.name

import argparse  # noqa: E402
import hashlib  # noqa: E402
import shutil  # noqa: E402
import socket  # noqa: E402
import ssl  # noqa: E402
import zipfile  # noqa: E402

from pypsrp.client import Client  # noqa: E402
from pypsrp.exceptions import WinRMError  # noqa: E402


def ps_quote(value):
    """Quote a string for PowerShell as a single-quoted literal."""
    return "'" + value.replace("'", "''") + "'"


def server_thumbprint(host, port):
    """SHA-1 thumbprint of the server certificate, in the upper-case hex form Windows shows."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=20) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            der = tls.getpeercert(binary_form=True)
    return hashlib.sha1(der).hexdigest().upper()


def connect(args):
    seen = server_thumbprint(args.host, args.port)
    if args.thumbprint and seen != args.thumbprint.replace(" ", "").upper():
        sys.exit(f"winrm_client: server certificate thumbprint {seen} does not match --thumbprint {args.thumbprint}")
    if args.command == "info":
        print(f"server certificate thumbprint: {seen}")
    return Client(
        args.host,
        port=args.port,
        ssl=True,
        auth="certificate",
        certificate_pem=args.cert,
        certificate_key_pem=args.key,
        cert_validation=False,  # self-signed; checked by thumbprint above
        connection_timeout=30,
        operation_timeout=20,
        read_timeout=30,
    )


def run(client, script):
    output, streams, had_errors = client.execute_ps(script)
    for record in streams.information:
        text = str(record.message_data)
        if text:
            print(text, file=sys.stderr)
    if output:
        print(output)
    for err in streams.error:
        print(f"ERROR: {err}", file=sys.stderr)
    return had_errors


def run_checked(client, script, what):
    if run(client, script):
        raise RuntimeError(f"{what} failed (see the errors above)")


def push(client, local_dir, remote_dir):
    with tempfile.TemporaryDirectory() as tmp:
        archive = shutil.make_archive(os.path.join(tmp, "push"), "zip", local_dir)
        remote_zip = remote_dir.rstrip("\\") + ".zip"
        run_checked(client, f"New-Item -ItemType Directory -Force -Path (Split-Path {ps_quote(remote_zip)} -Parent) | Out-Null", "creating the folder")
        client.copy(archive, remote_zip)
    run_checked(
        client,
        f"Remove-Item {ps_quote(remote_dir)} -Recurse -Force -ErrorAction SilentlyContinue; "
        f"Expand-Archive -Path {ps_quote(remote_zip)} -DestinationPath {ps_quote(remote_dir)} -Force; "
        f"Remove-Item {ps_quote(remote_zip)} -Force",
        "unpacking the scripts",
    )


def pull(client, remote_dir, local_dir):
    remote_zip = remote_dir.rstrip("\\") + "-pull.zip"
    run_checked(client, f"Compress-Archive -Path (Join-Path {ps_quote(remote_dir)} '*') -DestinationPath {ps_quote(remote_zip)} -Force", f"packing {remote_dir}")
    os.makedirs(local_dir, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        local_zip = os.path.join(tmp, "pull.zip")
        client.fetch(remote_zip, local_zip)
        with zipfile.ZipFile(local_zip) as z:
            for name in z.namelist():
                target = os.path.realpath(os.path.join(local_dir, name.replace("\\", "/")))
                if not target.startswith(os.path.realpath(local_dir) + os.sep):
                    sys.exit(f"winrm_client: refusing to extract {name} outside {local_dir}")
            z.extractall(local_dir)
    run(client, f"Remove-Item {ps_quote(remote_zip)} -Force")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5986)
    p.add_argument("--cert", required=True, help="client certificate (PEM)")
    p.add_argument("--key", required=True, help="client private key (PEM)")
    p.add_argument("--thumbprint", help="expected server certificate SHA-1 thumbprint")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("info")
    s = sub.add_parser("push")
    s.add_argument("local_dir")
    s.add_argument("remote_dir")
    s = sub.add_parser("run")
    s.add_argument("script")
    s = sub.add_parser("pull")
    s.add_argument("remote_dir")
    s.add_argument("local_dir")
    args = p.parse_args()

    try:
        client = connect(args)
        if args.command == "info":
            run(
                client,
                "$id = [Security.Principal.WindowsIdentity]::GetCurrent(); "
                "'computer: ' + $env:COMPUTERNAME; 'user: ' + $id.Name; "
                "'elevated: ' + (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
            )
        elif args.command == "push":
            push(client, args.local_dir, args.remote_dir)
        elif args.command == "run":
            if run(client, args.script):
                sys.exit(1)
        elif args.command == "pull":
            pull(client, args.remote_dir, args.local_dir)
    except (OSError, ValueError, RuntimeError, WinRMError) as exc:
        # Connection, TLS and WinRM errors (requests errors derive from OSError).
        sys.exit(f"winrm_client: {type(exc).__name__}: {exc}")
    finally:
        os.unlink(_TLS12_CONF.name)


if __name__ == "__main__":
    main()
