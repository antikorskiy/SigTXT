#!/usr/bin/env python3

import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path

import click
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from quantum_safe import HybridKEM, HybridSign
from quantum_safe.protocols import Envelope, SealedMessage
from quantum_safe.types.keys import SecretKey, PublicKey
from quantum_safe.types import SignedMessage

BACKEND = "pyca"
MAGIC = b"SIGTXT\x02"
VERSION = 2

DEFAULT_SIGN_ALGO = "Ed25519+ML-DSA-65-v2"
DEFAULT_KEM_ALGO = "X25519+ML-KEM-768"
CNSA2_SIGN_ALGO = "ML-DSA-87"
CNSA2_KEM_ALGO = "ML-KEM-1024"

ALLOWED_SIGN_ALGOS = {DEFAULT_SIGN_ALGO, CNSA2_SIGN_ALGO}
ALLOWED_KEM_ALGOS = {DEFAULT_KEM_ALGO, CNSA2_KEM_ALGO}

KDF_PROFILES = {
    1: {"name": "high", "time": 1, "memory": 2 * 1024 * 1024, "parallelism": 4, "hash_len": 32},
    2: {"name": "reduced", "time": 2, "memory": 256 * 1024, "parallelism": 4, "hash_len": 32},
}
DEFAULT_KDF_VERSION = 1

REPLAY_TTL_DAYS = 90
VACUUM_INTERVAL_HOURS = 24

_sigtxt_home = os.environ.get("SIGTXT_HOME")
REPLAY_DB = (Path(_sigtxt_home) if _sigtxt_home else Path.home() / ".sigtxt") / "replay.db"

MAX_HEADER_BYTES = 64 * 1024
MAX_SIG_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 1 << 30

DEFAULT_TTL_DAYS = 30
CLOCK_SKEW_MINUTES = 5

_ID_RE = re.compile(r"^[a-z0-9@._+-]{1,128}$")


class KeyLoadError(Exception):
    """Raised when a keypair file cannot be read, parsed, or decrypted."""


def _signer(cnsa2=False):
    if cnsa2:
        from quantum_safe.compliance import cnsa2
        return cnsa2.pqc_sign()
    return HybridSign(backend=BACKEND)


def _kem(cnsa2=False):
    if cnsa2:
        from quantum_safe.compliance import cnsa2
        return cnsa2.pqc_kem()
    return HybridKEM(backend=BACKEND)


def _pack_key(obj) -> dict:
    blob = obj.to_cbor()
    if isinstance(blob, (bytes, bytearray)):
        return {"enc": "b64", "data": base64.b64encode(bytes(blob)).decode()}
    return {"enc": "str", "data": str(blob)}


def _unpack_key(obj: dict, cls):
    blob = base64.b64decode(obj["data"]) if obj["enc"] == "b64" else obj["data"]
    return cls.from_cbor(blob)


def _fingerprint(public_obj) -> str:
    blob = public_obj.to_cbor()
    if isinstance(blob, str):
        blob = blob.encode()
    return "sha3:" + hashlib.sha3_256(bytes(blob)).hexdigest()[:32]


def _canon_id(s: str) -> str:
    if not isinstance(s, str):
        raise ValueError("ID must be a string")
    c = s.strip().lower()
    if not _ID_RE.match(c):
        raise ValueError(f"invalid ID: {s!r} (allowed: a-z 0-9 @ . _ + -)")
    return c


def _detect_profile(hdr: bytes) -> bool:
    try:
        meta = json.loads(hdr.decode())
    except Exception as e:
        raise ValueError(f"cannot parse header: {e}")
    sa = meta.get("signature_algorithm")
    ka = meta.get("kem_algorithm")
    if sa not in ALLOWED_SIGN_ALGOS:
        raise ValueError(f"unsupported signature_algorithm: {sa}")
    if ka not in ALLOWED_KEM_ALGOS:
        raise ValueError(f"unsupported kem_algorithm: {ka}")
    if sa == CNSA2_SIGN_ALGO and ka != CNSA2_KEM_ALGO:
        raise ValueError("mismatched algorithms in header (cnsa2 sign + non-cnsa2 kem)")
    if sa == DEFAULT_SIGN_ALGO and ka != DEFAULT_KEM_ALGO:
        raise ValueError("mismatched algorithms in header (default sign + non-default kem)")
    return ka == CNSA2_KEM_ALGO


def _wipe(buf: bytearray):
    for i in range(len(buf)):
        buf[i] = 0


def _derive_key(password: str, salt: bytes, kdf_version: int) -> bytes:
    params = KDF_PROFILES.get(kdf_version)
    if params is None:
        raise ValueError(f"unsupported kdf_version: {kdf_version}")
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params["time"],
        memory_cost=params["memory"],
        parallelism=params["parallelism"],
        hash_len=params["hash_len"],
        type=Type.ID,
    )


def _encrypt_with_password(plaintext: bytes, password: str, kdf_version: int) -> dict:
    salt = os.urandom(16)
    key = bytearray(_derive_key(password, salt, kdf_version))
    try:
        nonce = os.urandom(12)
        aead = ChaCha20Poly1305(bytes(key))
        ct = aead.encrypt(nonce, plaintext, None)
    finally:
        _wipe(key)
    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
    }


def _decrypt_with_password(blob: dict, password: str, kdf_version: int) -> bytes:
    salt = base64.b64decode(blob["salt"])
    nonce = base64.b64decode(blob["nonce"])
    ct = base64.b64decode(blob["ct"])
    key = bytearray(_derive_key(password, salt, kdf_version))
    try:
        aead = ChaCha20Poly1305(bytes(key))
        return aead.decrypt(nonce, ct, None)
    finally:
        _wipe(key)


def _fsync_dir(path: Path):
    try:
        dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    except (OSError, AttributeError):
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def _atomic_replace(tmp: Path, dst: Path):
    os.replace(tmp, dst)
    _fsync_dir(dst.parent)


def _write_secure_json(path: Path, data: dict, force: bool = False):
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(data, indent=2)

    if force:
        tmp = path.with_name(f"{path.name}.tmp.{secrets.token_hex(4)}")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            _atomic_replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    else:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise click.ClickException(f"{path} exists, use --force to overwrite")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise


def _write_bytes_secure(path: Path, data: bytes, force: bool = False, mode: int = 0o644):
    path.parent.mkdir(parents=True, exist_ok=True)

    if force:
        tmp = path.with_name(f"{path.name}.tmp.{secrets.token_hex(4)}")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            _atomic_replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    else:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        except FileExistsError:
            raise click.ClickException(f"{path} exists, use --force to overwrite")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise


def _resolve_password(password, password_file):
    if password:
        return password
    if password_file:
        pw = Path(password_file).read_text().strip()
        if not pw:
            raise click.ClickException(f"{password_file}: password file is empty")
        return pw
    return None


def _prompt_password(prompt: str, confirm: bool = False) -> str:
    pw = getpass.getpass(prompt)
    if not pw:
        raise click.ClickException("password cannot be empty")
    if confirm:
        if getpass.getpass("Confirm password: ") != pw:
            raise click.ClickException("passwords do not match")
    return pw


def _save_kp(path: Path, kp, key_type: str, password: str | None,
             owner: str | None, profile: str, force: bool = False,
             kdf_version: int = DEFAULT_KDF_VERSION):
    if isinstance(kp, dict):
        secret_obj = kp["secret"]
        public_obj = kp["public"]
    else:
        secret_obj = kp.secret
        public_obj = kp.public

    secret_cbor = secret_obj.to_cbor()
    if isinstance(secret_cbor, str):
        secret_cbor = secret_cbor.encode()
    secret_cbor_buf = bytearray(secret_cbor)

    try:
        if password:
            secret_blob = _encrypt_with_password(bytes(secret_cbor_buf), password, kdf_version)
            secret_enc = "password"
        else:
            secret_blob = _pack_key(secret_obj)
            secret_enc = None
            kdf_version = None
    finally:
        _wipe(secret_cbor_buf)

    canon_owner = _canon_id(owner) if owner else None

    payload = {
        "type": key_type,
        "owner": canon_owner,
        "profile": profile,
        "fingerprint": _fingerprint(public_obj),
        "secret_enc": secret_enc,
        "kdf_version": kdf_version,
        "secret": secret_blob,
        "public": _pack_key(public_obj),
    }
    _write_secure_json(path, payload, force=force)


def _load_kp(path: Path, password: str | None = None,
             password_file: str | None = None, public_only: bool = False) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise KeyLoadError(f"{path}: cannot read key file ({type(e).__name__})")

    if "public" not in data:
        raise KeyLoadError(f"{path}: missing 'public' field")

    profile = data.get("profile", "default")
    try:
        public_obj = _unpack_key(data["public"], PublicKey)
    except Exception as e:
        raise KeyLoadError(f"{path}: invalid public key ({type(e).__name__})")

    actual_fp = _fingerprint(public_obj)
    stored_fp = data.get("fingerprint")
    if stored_fp and not hmac.compare_digest(stored_fp, actual_fp):
        raise KeyLoadError(f"{path}: stored fingerprint does not match public key")

    if public_only:
        return {
            "type": data.get("type"),
            "owner": data.get("owner"),
            "profile": profile,
            "fingerprint": actual_fp,
            "secret": None,
            "public": public_obj,
        }

    secret = data.get("secret")
    if not isinstance(secret, dict):
        raise KeyLoadError(f"{path}: invalid key format")

    if data.get("secret_enc") == "password":
        pw = _resolve_password(password, password_file)
        if not pw:
            if os.isatty(0):
                pw = getpass.getpass(f"Password for {path}: ")
            else:
                raise KeyLoadError(
                    f"{path}: private key is password-protected "
                    f"(use --password, --password-file, or SIGTXT_PASSWORD)"
                )
        kdf_version = data.get("kdf_version", 1)
        try:
            raw = bytearray(_decrypt_with_password(secret, pw, kdf_version))
        except Exception as e:
            raise KeyLoadError(f"{path}: key unlock failed ({type(e).__name__})")
        try:
            secret_obj = SecretKey.from_cbor(bytes(raw))
        finally:
            _wipe(raw)
    else:
        try:
            secret_obj = _unpack_key(secret, SecretKey)
        except Exception as e:
            raise KeyLoadError(f"{path}: invalid secret key ({type(e).__name__})")

    return {
        "type": data.get("type"),
        "owner": data.get("owner"),
        "profile": profile,
        "fingerprint": actual_fp,
        "secret": secret_obj,
        "public": public_obj,
    }


def _stamp(s, r, c, n, text_bytes):
    prefix_hash = hashlib.sha3_256(text_bytes[:64]).hexdigest()[:16]
    material = f"{s}|{r}|{c}|{n}|{prefix_hash}".encode()
    return hashlib.sha3_256(material).hexdigest()


def _header(sender, recipient, subject, size, enc, cenc, ctype,
            created_at, not_after, stamp, sign_algo, kem_algo,
            signer_fp, recipient_fp) -> bytes:
    return json.dumps({
        "subject": subject,
        "sender_id": sender,
        "recipient_id": recipient,
        "created_at": created_at,
        "not_after": not_after,
        "unique_stamp": stamp,
        "size_bytes": size,
        "encoding": enc,
        "content_encoding": cenc,
        "content_type": ctype,
        "signature_algorithm": sign_algo,
        "kem_algorithm": kem_algo,
        "signer_fingerprint": signer_fp,
        "recipient_fingerprint": recipient_fp,
    }, sort_keys=True, separators=(",", ":")).encode()


def _sign_cbor(payload_bytes: bytes, secret, context: bytes, cnsa2=False) -> bytes:
    signer = _signer(cnsa2)
    sm = signer.sign(payload_bytes, secret, context=context)
    return sm.to_cbor()


def _verify_sm_cbor(sm_cbor: bytes, pub, context: bytes, cnsa2=False):
    sm = SignedMessage.from_cbor(sm_cbor)
    signer = _signer(cnsa2)
    signer.verify(sm, pub, context=context)


def _seal_envelope(inner: bytes, public) -> bytes:
    sealed = Envelope.seal(inner, public)
    return sealed.to_bytes() if hasattr(sealed, "to_bytes") else bytes(sealed)


def _open_envelope(ct: bytes, secret) -> bytes:
    sealed = SealedMessage.from_bytes(ct)
    return Envelope.open(sealed, secret)


def _parse_container(data: bytes):
    mlen = len(MAGIC)
    if len(data) > MAX_TOTAL_BYTES:
        raise ValueError("file too large")
    if len(data) < mlen + 1 + 4 + 2:
        raise ValueError("file too short")
    if data[:mlen] != MAGIC:
        raise ValueError(f"not a .sigtxt v2 file (got {data[:mlen]!r})")
    if data[mlen] != VERSION:
        raise ValueError(f"unsupported version: {data[mlen]}")

    pos = mlen + 1
    if len(data) < pos + 4:
        raise ValueError("truncated file")
    (hlen,) = struct.unpack(">I", data[pos:pos + 4]); pos += 4
    if hlen > MAX_HEADER_BYTES:
        raise ValueError("header too large")
    if len(data) < pos + hlen + 2:
        raise ValueError("truncated file")
    hdr = data[pos:pos + hlen]; pos += hlen
    (hslen,) = struct.unpack(">H", data[pos:pos + 2]); pos += 2
    if hslen > MAX_SIG_BYTES:
        raise ValueError("signature too large")
    if len(data) < pos + hslen:
        raise ValueError("truncated file")
    hsig_cbor = data[pos:pos + hslen]; pos += hslen
    ct = data[pos:]

    detected_cnsa = _detect_profile(hdr)
    return hdr, hsig_cbor, ct, detected_cnsa


def _parse_inner(inner: bytes):
    if len(inner) < 2:
        raise ValueError("envelope payload too short")
    if len(inner) > MAX_TOTAL_BYTES:
        raise ValueError("envelope payload too large")
    (pslen,) = struct.unpack(">H", inner[:2])
    if pslen > MAX_SIG_BYTES:
        raise ValueError("payload signature too large")
    if len(inner) < 2 + pslen:
        raise ValueError("truncated payload")
    return inner[2:2 + pslen], inner[2 + pslen:]


def _replay_conn() -> sqlite3.Connection:
    REPLAY_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(REPLAY_DB, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS seen ("
        "  stamp TEXT PRIMARY KEY,"
        "  seen_at TEXT NOT NULL"
        ")"
    )
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    now = datetime.now(timezone.utc)
    row = conn.execute("SELECT value FROM meta WHERE key='last_vacuum'").fetchone()
    need_vacuum = True
    if row:
        try:
            last = datetime.fromisoformat(row[0])
            need_vacuum = (now - last) > timedelta(hours=VACUUM_INTERVAL_HOURS)
        except Exception:
            need_vacuum = True
    if need_vacuum:
        cutoff = (now - timedelta(days=REPLAY_TTL_DAYS)).isoformat()
        conn.execute("DELETE FROM seen WHERE seen_at < ?", (cutoff,))
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('last_vacuum', ?)",
            (now.isoformat(),),
        )
        conn.commit()
    return conn


def _check_and_mark_read(stamp: str) -> bool:
    conn = _replay_conn()
    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO seen (stamp, seen_at) VALUES (?, ?)",
            (stamp, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return cur.rowcount == 0
    finally:
        conn.close()


def seal(payload, subject, signer_secret, recipient_public,
         signer_fingerprint, recipient_fingerprint,
         encoding="utf-8", content_encoding="identity", content_type="text/plain",
         cnsa2=False, ttl_days=DEFAULT_TTL_DAYS) -> bytes:
    meta = payload["meta"]
    sender = meta["sender_id"]
    recipient = meta["recipient_id"]

    text_bytes = payload["text"].encode(encoding)
    nonce = secrets.token_hex(32)
    now = datetime.now(timezone.utc)
    created_at = now.isoformat().replace("+00:00", "Z")
    not_after = (now + timedelta(days=ttl_days)).isoformat().replace("+00:00", "Z")
    stamp = _stamp(sender, recipient, created_at, nonce, text_bytes)

    sign_algo = CNSA2_SIGN_ALGO if cnsa2 else DEFAULT_SIGN_ALGO
    kem_algo = CNSA2_KEM_ALGO if cnsa2 else DEFAULT_KEM_ALGO

    hdr = _header(sender, recipient, subject, len(text_bytes), encoding,
                  content_encoding, content_type, created_at, not_after,
                  stamp, sign_algo, kem_algo,
                  signer_fingerprint, recipient_fingerprint)
    if len(hdr) > MAX_HEADER_BYTES:
        raise ValueError(f"header too large: {len(hdr)} > {MAX_HEADER_BYTES}")

    header_sm_cbor = _sign_cbor(hdr, signer_secret, b"sigtxt-header-v2", cnsa2)

    full = {
        "meta": {
            **meta, "subject": subject, "created_at": created_at,
            "unique_stamp": stamp, "nonce": nonce,
            "size_bytes": len(text_bytes), "encoding": encoding,
            "content_encoding": content_encoding,
        },
        "text": payload["text"],
    }
    body = json.dumps(full, sort_keys=True, separators=(",", ":")).encode()

    bound = hashlib.sha3_256(hdr).digest() + body
    body_sm_cbor = _sign_cbor(bound, signer_secret, b"sigtxt-payload-v2", cnsa2)
    if len(body_sm_cbor) > 0xFFFF:
        raise ValueError(f"payload signature too long: {len(body_sm_cbor)}")

    inner = struct.pack(">H", len(body_sm_cbor)) + body_sm_cbor + body
    ct = _seal_envelope(inner, recipient_public)

    out = bytearray()
    out += MAGIC
    out.append(VERSION)
    out += struct.pack(">I", len(hdr)); out += hdr
    out += struct.pack(">H", len(header_sm_cbor)); out += header_sm_cbor
    out += ct

    if len(out) > MAX_TOTAL_BYTES:
        raise ValueError(f"container too large: {len(out)} > {MAX_TOTAL_BYTES}")
    return bytes(out)


def verify_header(hdr: bytes, hsig_cbor: bytes, public, cnsa2=False) -> dict:
    _verify_sm_cbor(hsig_cbor, public, b"sigtxt-header-v2", cnsa2)
    return json.loads(hdr.decode())


def _check_fingerprints(header: dict, signer_public, my_public):
    sfp = header.get("signer_fingerprint")
    if sfp:
        expected = _fingerprint(signer_public)
        if not hmac.compare_digest(sfp, expected):
            raise ValueError("signer fingerprint mismatch")

    rfp = header.get("recipient_fingerprint")
    if rfp and my_public is not None:
        expected = _fingerprint(my_public)
        if not hmac.compare_digest(rfp, expected):
            raise ValueError("recipient fingerprint mismatch")


def _check_time(header: dict):
    try:
        created = datetime.fromisoformat(header["created_at"].replace("Z", "+00:00"))
    except Exception:
        raise ValueError("invalid created_at in header")
    now = datetime.now(timezone.utc)
    skew = created - now
    if skew > timedelta(minutes=CLOCK_SKEW_MINUTES):
        raise ValueError(
            f"created_at {header['created_at']} is in the future by {skew} "
            f"(check system clock; allowed skew: {CLOCK_SKEW_MINUTES} min)"
        )
    if "not_after" in header:
        try:
            not_after = datetime.fromisoformat(header["not_after"].replace("Z", "+00:00"))
        except Exception:
            raise ValueError("invalid not_after in header")
        if now > not_after:
            raise ValueError(f"message expired at {header['not_after']}")


def open_sigtxt(data: bytes, recipient_secret, signer_public,
                my_public=None,
                signer_owner: str | None = None,
                recipient_owner: str | None = None,
                expected_cnsa: bool | None = None,
                warn_legacy: bool = False):
    hdr, hsig_cbor, ct, detected_cnsa = _parse_container(data)

    if expected_cnsa is not None and expected_cnsa != detected_cnsa:
        expected_name = "cnsa2" if expected_cnsa else "default"
        detected_name = "cnsa2" if detected_cnsa else "default"
        raise ValueError(
            f"profile mismatch: expected {expected_name}, file is {detected_name}"
        )

    header = verify_header(hdr, hsig_cbor, signer_public, detected_cnsa)
    _check_fingerprints(header, signer_public, my_public)

    if warn_legacy and (
        "signer_fingerprint" not in header or "recipient_fingerprint" not in header
    ):
        click.echo(
            "WARNING: header has no fingerprint(s) (legacy file); "
            "key pinning was not verified",
            err=True,
        )

    if signer_owner:
        expected = _canon_id(signer_owner)
        if header["sender_id"] != expected:
            raise ValueError(
                f"sender_id '{header['sender_id']}' does not match key owner '{expected}'"
            )
    if recipient_owner:
        expected = _canon_id(recipient_owner)
        if header["recipient_id"] != expected:
            raise ValueError(
                f"recipient_id '{header['recipient_id']}' does not match key owner '{expected}'"
            )

    _check_time(header)

    inner = _open_envelope(ct, recipient_secret)
    psig_cbor, pbody = _parse_inner(inner)

    bound = hashlib.sha3_256(hdr).digest() + pbody
    _verify_sm_cbor(psig_cbor, signer_public, b"sigtxt-payload-v2", detected_cnsa)

    full = json.loads(pbody.decode())
    meta = full["meta"]

    if not hmac.compare_digest(meta["unique_stamp"], header["unique_stamp"]):
        raise ValueError("unique_stamp mismatch")
    if not hmac.compare_digest(meta["subject"], header["subject"]):
        raise ValueError("subject mismatch")

    try:
        text_bytes = full["text"].encode(header["encoding"])
    except (LookupError, UnicodeEncodeError) as e:
        raise ValueError(f"invalid encoding in header: {e}")
    if len(text_bytes) != header["size_bytes"]:
        raise ValueError("size_bytes mismatch")

    was_already_read = _check_and_mark_read(header["unique_stamp"])
    return header, full, was_already_read


@click.group()
def cli():
    """sigtxt - post-quantum container."""


@cli.command()
@click.argument("output", type=click.Path(dir_okay=False))
@click.option("--type", "key_type", type=click.Choice(["sign", "kem"]), default="sign")
@click.option("--owner", default=None, help="key owner ID (required unless --allow-no-owner)")
@click.option("--password", default=None, envvar="SIGTXT_PASSWORD")
@click.option("--password-file", default=None, type=click.Path(exists=True, dir_okay=False))
@click.option("--no-password", is_flag=True, help="store key unencrypted (insecure)")
@click.option("--kdf-profile", type=click.Choice(["1", "2"]), default="1", show_default=True)
@click.option("--cnsa", is_flag=True, help="CNSA 2.0: ML-KEM-1024 + ML-DSA-87")
@click.option("--allow-no-owner", is_flag=True, help="skip owner binding (insecure)")
@click.option("--force", is_flag=True, help="overwrite existing file")
def keygen(output, key_type, owner, password, password_file, no_password,
           kdf_profile, cnsa, allow_no_owner, force):
    """Generate a keypair."""
    try:
        if not owner and not allow_no_owner:
            raise click.ClickException(
                "--owner is required (or pass --allow-no-owner to skip owner binding)"
            )

        if no_password and (password or password_file):
            raise click.ClickException(
                "--no-password conflicts with --password, --password-file, "
                "or SIGTXT_PASSWORD"
            )

        pw = _resolve_password(password, password_file)
        if pw is None and no_password:
            click.echo(
                "WARNING: storing key WITHOUT password protection (--no-password)",
                err=True,
            )
        elif pw is None:
            if os.isatty(0):
                pw = _prompt_password("Password for new key: ", confirm=True)
            else:
                raise click.ClickException(
                    "no password provided (use --password, --password-file, "
                    "SIGTXT_PASSWORD, or --no-password)"
                )

        profile = "cnsa2" if cnsa else "default"
        if key_type == "sign":
            kp = _signer(cnsa).generate_keypair()
        else:
            kp = _kem(cnsa).generate_keypair()
        _save_kp(Path(output), kp, key_type, pw, owner, profile,
                 force=force, kdf_version=int(kdf_profile))
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e))

    enc_note = f" (password, kdf={kdf_profile})" if pw else " (no password)"
    fp = _fingerprint(kp.public)
    click.echo(f"OK: {key_type} keys -> {output}{enc_note}")
    click.echo(f"    fingerprint: {fp}")
    click.echo(f"    profile: {profile}")


@cli.command("export-pub")
@click.argument("key_file", type=click.Path(exists=True, dir_okay=False))
@click.argument("output", type=click.Path(dir_okay=False))
@click.option("--force", is_flag=True, help="overwrite existing file")
def export_pub(key_file, output, force):
    """Export only the public part of a keypair."""
    try:
        kp = _load_kp(Path(key_file), public_only=True)
        payload = {
            "type": kp["type"],
            "owner": kp["owner"],
            "profile": kp["profile"],
            "fingerprint": _fingerprint(kp["public"]),
            "public": _pack_key(kp["public"]),
        }
        _write_secure_json(Path(output), payload, force=force)
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e))
    click.echo(f"OK: {output}")
    click.echo(f"    fingerprint: {payload['fingerprint']}")
    click.echo(f"    owner: {payload['owner']}")
    click.echo(f"    profile: {payload['profile']}")


@cli.command("change-password")
@click.argument("key_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--old-password", default=None, envvar="SIGTXT_OLD_PASSWORD")
@click.option("--old-password-file", default=None, type=click.Path(exists=True, dir_okay=False))
@click.option("--new-password", default=None, envvar="SIGTXT_NEW_PASSWORD")
@click.option("--new-password-file", default=None, type=click.Path(exists=True, dir_okay=False))
@click.option("--kdf-profile", type=click.Choice(["1", "2"]), default="1", show_default=True)
def change_password(key_file, old_password, old_password_file,
                    new_password, new_password_file, kdf_profile):
    """Change the password protecting a private key (key itself is preserved)."""
    try:
        old_pw = _resolve_password(old_password, old_password_file)
        if old_pw is None:
            old_pw = os.environ.get("SIGTXT_PASSWORD")
        if old_pw is None and os.isatty(0):
            old_pw = getpass.getpass("Old password: ")

        kp = _load_kp(Path(key_file), password=old_pw, password_file=old_password_file)
        if kp["secret"] is None:
            raise click.ClickException("key has no private part")
        if kp.get("type") not in ("sign", "kem"):
            raise click.ClickException(
                f"cannot change password: key has no valid 'type' "
                f"(got {kp.get('type')!r}); regenerate the key"
            )

        new_pw = _resolve_password(new_password, new_password_file)
        if new_pw is None:
            if os.isatty(0):
                new_pw = _prompt_password("New password: ", confirm=True)
            else:
                raise click.ClickException("no new password provided")

        _save_kp(
            Path(key_file), kp,
            kp["type"], new_pw, kp["owner"], kp["profile"],
            force=True, kdf_version=int(kdf_profile),
        )
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e))

    click.echo(f"OK: password changed for {key_file}")
    click.echo(f"    fingerprint unchanged: {_fingerprint(kp['public'])}")


@cli.command()
@click.argument("message_file", type=click.Path(exists=True, dir_okay=False))
@click.argument("output", type=click.Path(dir_okay=False))
@click.option("--sign-key", required=True, type=click.Path(exists=True))
@click.option("--to-key", required=True, type=click.Path(exists=True))
@click.option("--sender", required=True)
@click.option("--recipient", required=True)
@click.option("--subject", required=True)
@click.option("--password", default=None, envvar="SIGTXT_PASSWORD")
@click.option("--password-file", default=None, type=click.Path(exists=True, dir_okay=False))
@click.option("--encoding", default="utf-8", show_default=True)
@click.option("--content-type", default="text/plain", show_default=True)
@click.option("--cnsa", is_flag=True, help="require CNSA 2.0 profile")
@click.option("--ttl-days", default=DEFAULT_TTL_DAYS, show_default=True, type=int)
@click.option("--force", is_flag=True, help="overwrite output")
def sign(message_file, output, sign_key, to_key, sender, recipient, subject,
         password, password_file, encoding, content_type, cnsa, ttl_days, force):
    """Sign and encrypt a message -> .sigtxt"""
    try:
        sender_canon = _canon_id(sender)
        recipient_canon = _canon_id(recipient)
        text = Path(message_file).read_text(encoding=encoding)
        sk_obj = _load_kp(Path(sign_key), password, password_file)
        pk_obj = _load_kp(Path(to_key), public_only=True)

        key_profile = sk_obj["profile"]
        if pk_obj["profile"] != key_profile:
            raise click.ClickException(
                f"profile mismatch: sign-key is '{key_profile}', "
                f"to-key is '{pk_obj['profile']}'; both must match"
            )
        if cnsa and key_profile != "cnsa2":
            raise click.ClickException(
                "sign-key profile is 'default', but --cnsa requested; "
                "regenerate key with --cnsa"
            )
        use_cnsa2 = key_profile == "cnsa2"

        data = seal(
            {"meta": {"sender_id": sender_canon, "recipient_id": recipient_canon},
             "text": text},
            subject, sk_obj["secret"], pk_obj["public"],
            signer_fingerprint=sk_obj["fingerprint"],
            recipient_fingerprint=pk_obj["fingerprint"],
            encoding=encoding, content_encoding="identity", content_type=content_type,
            cnsa2=use_cnsa2, ttl_days=ttl_days,
        )
        _write_bytes_secure(Path(output), data, force=force, mode=0o644)
        click.echo(
            f"OK: {output} ({len(data)} bytes, "
            f"profile={'cnsa2' if use_cnsa2 else 'default'})"
        )
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e))


@cli.command(name="open")
@click.argument("sigtxt_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--my-key", required=True, type=click.Path(exists=True))
@click.option("--from-key", required=True, type=click.Path(exists=True))
@click.option("--password", default=None, envvar="SIGTXT_PASSWORD")
@click.option("--password-file", default=None, type=click.Path(exists=True, dir_okay=False))
@click.option("--out", type=click.Path(dir_okay=False), default=None)
@click.option("--header-only", is_flag=True)
@click.option("--cnsa", is_flag=True, help="require CNSA 2.0 profile")
@click.option("--allow-no-owner", is_flag=True, help="skip owner verification (insecure)")
def open_cmd(sigtxt_file, my_key, from_key, password, password_file, out,
             header_only, cnsa, allow_no_owner):
    """Decrypt and verify a .sigtxt file"""
    try:
        data = Path(sigtxt_file).read_bytes()
    except OSError as e:
        raise click.ClickException(f"{sigtxt_file}: cannot read ({type(e).__name__})")

    try:
        from_kp = _load_kp(Path(from_key), public_only=True)
        signer_pub = from_kp["public"]
        signer_owner = from_kp.get("owner")
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e))

    if not signer_owner and not allow_no_owner:
        raise click.ClickException(
            "from-key has no owner (sender_id would not be verified); "
            "regenerate with --owner or pass --allow-no-owner"
        )

    if header_only:
        try:
            hdr, hsig_cbor, _, detected_cnsa = _parse_container(data)
        except ValueError as e:
            raise click.ClickException(str(e))
        if cnsa and not detected_cnsa:
            raise click.ClickException("profile mismatch: --cnsa set but file is default profile")
        try:
            h = verify_header(hdr, hsig_cbor, signer_pub, detected_cnsa)
        except Exception as e:
            raise click.ClickException(f"header signature invalid: {e}")

        sfp = h.get("signer_fingerprint")
        if sfp:
            expected = _fingerprint(signer_pub)
            if not hmac.compare_digest(sfp, expected):
                raise click.ClickException("signer fingerprint mismatch")
            h["_signer_fingerprint_verified"] = True
        else:
            h["_signer_fingerprint_verified"] = False
            click.echo(
                "WARNING: header has no fingerprint(s) (legacy file)",
                err=True,
            )

        h["_recipient_fingerprint_verified"] = False
        click.echo(json.dumps(h, indent=2, ensure_ascii=False))
        return

    try:
        my_kp = _load_kp(Path(my_key), password, password_file)
        my_owner = my_kp.get("owner")
        if not my_owner and not allow_no_owner:
            raise click.ClickException(
                "my-key has no owner (recipient_id would not be verified); "
                "regenerate with --owner or pass --allow-no-owner"
            )
        _, payload, was_already_read = open_sigtxt(
            data, my_kp["secret"], signer_pub,
            my_public=my_kp["public"],
            signer_owner=signer_owner,
            recipient_owner=my_owner,
            expected_cnsa=True if cnsa else None,
            warn_legacy=True,
        )
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e))

    if was_already_read:
        click.echo("WARNING: this message has been read before", err=True)

    m = payload["meta"]
    click.echo("-" * 60)
    click.echo(f"  From:    {m['sender_id']}")
    click.echo(f"  To:      {m['recipient_id']}")
    click.echo(f"  Subject: {m['subject']}")
    click.echo(f"  Created: {m['created_at']}")
    click.echo(f"  Stamp:   {m['unique_stamp']}")
    click.echo(f"  Size:    {m['size_bytes']} bytes")
    click.echo("-" * 60)
    click.echo(payload["text"])

    if out:
        Path(out).write_text(payload["text"], encoding=m["encoding"])
        click.echo(f"\nOK: saved to {out}")


if __name__ == "__main__":
    cli()