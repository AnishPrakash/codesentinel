"""The comprehension gate. One question per critical finding.

PS3: 'Explanation alone is not sufficient; the user must be able to confirm
their understanding is correct.' This module is that requirement, implemented.

Questions ask for a mechanism, never a definition - 'what does an attacker
actually do' cannot be answered by pattern-matching the explanation text.
"""
from __future__ import annotations

import dataclasses

from ..models import Finding, Severity, Tier

QUESTIONS: dict[str, str] = {
    "CS001": (
        "This key is removed from the file and the fix is deployed. Explain why the "
        "credential is still considered compromised, and what you must do about it."
    ),
    "CS002": (
        "Describe what the database receives when someone submits the value "
        "1 OR 1=1 for this parameter, and why a parameterised query does not have "
        "the same outcome."
    ),
    "CS003": (
        "Explain what the shell does with the character ; inside this command string, "
        "and why passing an argument list instead removes the problem."
    ),
    "CS004": (
        "Explain why being fast makes a hash algorithm a bad choice for storing "
        "passwords."
    ),
    "CS005": (
        "A logged-in user changes the id in this URL to another user's id. Walk through "
        "what your handler does with that request, step by step, and name the check "
        "that is missing."
    ),
    "CS006": (
        "Explain how a package that does not exist can end up running code on your "
        "machine."
    ),
    "CS007": (
        "Someone puts a script tag into this value. Walk through what the browser does "
        "with the page, and whose session that script runs in."
    ),
    "CS008": (
        "A request asks for ../../../../etc/passwd. Explain what your code resolves that "
        "to, and why checking the path before resolving it does not help."
    ),
    "CS009": (
        "Explain what a website you have never heard of can do once this setting is at "
        "its most permissive value."
    ),
    "CS014": (
        "Explain what happens between the bytes arriving and your object existing, "
        "and why that step is different from parsing JSON."
    ),
    "CS015": (
        "The connection is still encrypted with this setting. Explain what you have "
        "lost anyway, and who can take advantage of it."
    ),
    "CS016": (
        "Name who can read this traffic between your process and the server, and say "
        "what they see."
    ),
    "CS017": (
        "The value is only in a log file, not in the database. Explain why that is "
        "still a disclosure, and who ends up able to read it."
    ),
    # Advisories carry no question. They are not confident enough to gate on,
    # and gating on a guess would teach the wrong lesson.
}

# Concepts a passing answer must demonstrate. Graded on ideas, not wording.
RUBRIC: dict[str, list[list[str]]] = {
    # each inner list is a concept; the answer must hit one synonym from each
    "CS001": [
        ["history", "git log", "previous commit", "already pushed", "logs", "clone"],
        ["revoke", "rotate", "regenerate", "invalidate", "new key"],
    ],
    "CS002": [
        ["always true", "1=1", "every row", "all rows", "whole table", "condition is true"],
        ["separate", "bound", "parameter", "not code", "as a value", "escaped", "placeholder"],
    ],
    "CS003": [
        ["second command", "another command", "separator", "chain", "runs both", "new command"],
        ["no shell", "argument list", "not parsed", "array", "execfile", "no interpretation"],
    ],
    "CS004": [
        ["brute", "guess", "billions", "fast", "many attempts", "crack", "rainbow"],
    ],
    "CS005": [
        ["returns", "gives", "responds with", "fetch", "reads"],
        ["other user", "someone else", "not theirs", "another account", "not the owner"],
        ["ownership", "owner", "belongs", "authorisation", "authorization", "who owns",
         "user_id"],
    ],
    "CS006": [
        ["register", "claim", "publish", "upload", "take the name", "squat"],
        ["install", "pip", "npm", "download", "runs", "executes"],
    ],
    "CS007": [
        ["executes", "runs", "parsed", "treated as", "interpreted", "renders"],
        ["other user", "another user", "victim", "whoever views", "their session",
         "their browser", "everyone who"],
    ],
    "CS008": [
        ["outside", "escapes", "above", "parent", "different directory", "etc/passwd",
         "anywhere"],
        ["resolve", "resolved", "after", "normalis", "normaliz", "expand", "too late"],
    ],
    "CS009": [
        ["any site", "any origin", "any website", "anyone", "every origin", "attacker site"],
        ["credential", "cookie", "logged in", "authenticated", "as the user", "session"],
    ],
    "CS014": [
        ["construct", "instantiate", "creates object", "rebuild", "runs", "executes",
         "calls", "constructor", "class"],
        ["json", "data only", "plain object", "cannot name", "no code", "just data",
         "no class"],
    ],
    "CS015": [
        ["identity", "who", "proof", "authenticity", "which server", "hostname",
         "not verified", "any certificate", "impersonat"],
        ["middle", "mitm", "intercept", "between", "proxy", "wifi", "router",
         "on the path", "eavesdrop"],
    ],
    "CS016": [
        ["anyone", "middle", "network", "wifi", "isp", "proxy", "router", "sniff",
         "on the path", "provider"],
        ["plain", "cleartext", "unencrypted", "readable", "everything", "token",
         "password", "credential", "cookie", "body"],
    ],
    "CS017": [
        ["log", "file", "aggregat", "shipped", "stored", "kept", "copy"],
        ["support", "anyone with access", "more people", "team", "admin", "operator",
         "third party", "vendor", "dashboard", "whoever can read"],
    ],
}


def attach_question(finding: Finding) -> Finding:
    """Gate CRITICAL *deterministic* findings only.

    Two exclusions, both deliberate. Asking a comprehension question about a weak
    hash is pedantry. And gating on an advisory would be worse than pedantry - it
    would make someone prove they understand a problem we are not confident exists,
    which teaches them to distrust the question.

    `cs learn CS008` still works for any class that has a question; this only
    controls what a scan gates on automatically.
    """
    if finding.tier is not Tier.DETERMINISTIC:
        return finding
    if finding.severity < Severity.CRITICAL:
        return finding
    q = QUESTIONS.get(finding.rule_id, "")
    return dataclasses.replace(finding, question=q) if q else finding
