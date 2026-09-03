"""Import name to distribution name, where they differ.

CS006 sees what the code writes - `import yaml`. The manifest holds what the
registry publishes - `pyyaml`. Those are the same package, and for the most
common libraries in Python they are spelled differently. Hyphen and underscore
normalisation covers `tree_sitter_java` -> `tree-sitter-java` but nothing
reaches `cv2` -> `opencv-python`.

Without this table the firewall reports `import yaml` as an unrecognised
dependency, which is both wrong and the most embarrassing kind of wrong: it is
the single most common non-stdlib import in Python.

Entries are import-name -> distribution names. Add both directions of anything
new; the firewall and scripts/build_manifests.py both read this one table, so
they cannot drift apart.
"""
from __future__ import annotations

IMPORT_TO_DISTRIBUTION: dict[str, set[str]] = {
    # --- serialisation / config ---
    "yaml": {"pyyaml"},
    "toml": {"toml", "tomli"},
    "ruamel": {"ruamel.yaml", "ruamel-yaml"},
    "dotenv": {"python-dotenv"},
    "jsonschema": {"jsonschema"},
    "msgpack": {"msgpack"},
    "ujson": {"ujson"},

    # --- imaging / media ---
    "cv2": {"opencv-python", "opencv-python-headless", "opencv-contrib-python"},
    "PIL": {"pillow"},
    "skimage": {"scikit-image"},
    "fitz": {"pymupdf"},
    "wand": {"wand"},

    # --- science / ML ---
    "sklearn": {"scikit-learn"},
    "torch": {"torch"},
    "tensorflow": {"tensorflow"},
    "cupy": {"cupy"},
    "lightgbm": {"lightgbm"},

    # --- web / scraping ---
    "bs4": {"beautifulsoup4"},
    "lxml": {"lxml"},
    "requests_toolbelt": {"requests-toolbelt"},
    "google": {"google-api-core", "googleapis-common-protos", "protobuf"},

    # --- crypto / auth ---
    "jwt": {"pyjwt"},
    "jose": {"python-jose"},
    "OpenSSL": {"pyopenssl"},
    "Crypto": {"pycryptodome"},
    "Cryptodome": {"pycryptodomex"},
    "nacl": {"pynacl"},
    "argon2": {"argon2-cffi"},
    "bcrypt": {"bcrypt"},

    # --- databases ---
    "psycopg2": {"psycopg2-binary", "psycopg2"},
    "MySQLdb": {"mysqlclient"},
    "pymysql": {"pymysql"},
    "sqlalchemy": {"sqlalchemy"},

    # --- documents ---
    "docx": {"python-docx"},
    "pptx": {"python-pptx"},
    "openpyxl": {"openpyxl"},
    "xlrd": {"xlrd"},

    # --- system / misc ---
    "dateutil": {"python-dateutil"},
    "serial": {"pyserial"},
    "usb": {"pyusb"},
    "magic": {"python-magic"},
    "attr": {"attrs"},
    "attrs": {"attrs"},
    "pkg_resources": {"setuptools"},
    "setuptools": {"setuptools"},
    "win32com": {"pywin32"},
    "win32api": {"pywin32"},
    "pythoncom": {"pywin32"},
    "slugify": {"python-slugify"},
    "multipart": {"python-multipart"},
    "socketio": {"python-socketio"},
    "engineio": {"python-engineio"},
    "memcache": {"python-memcached"},
    "ldap": {"python-ldap"},
    "Levenshtein": {"python-levenshtein", "levenshtein"},
    "editdistance": {"editdistance"},
    "yattag": {"yattag"},

    # --- what CodeSentinel itself imports ---
    "llama_cpp": {"llama-cpp-python"},
}

# Flat lookup: every spelling that should be accepted for a given import name.
ALL_KNOWN_SPELLINGS: set[str] = {
    name.lower() for name in IMPORT_TO_DISTRIBUTION
} | {
    dist.lower() for dists in IMPORT_TO_DISTRIBUTION.values() for dist in dists
}


def distributions_for(import_name: str) -> set[str]:
    """Distribution names an import could come from. Empty when unknown."""
    return {d.lower() for d in IMPORT_TO_DISTRIBUTION.get(import_name, set())} | {
        d.lower() for d in IMPORT_TO_DISTRIBUTION.get(import_name.lower(), set())
    }
