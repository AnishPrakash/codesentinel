"""Build offline package manifests. Run before the hackathon, commit the result.

Producing these at scan time would defeat the point: resolving a name against a
live registry is exactly the action a slopsquatted package wants you to take.
"""
from pathlib import Path

import httpx

OUT = Path(__file__).resolve().parent.parent / "codesentinel" / "data" / "manifests"
OUT.mkdir(parents=True, exist_ok=True)


def pypi(n: int = 8000) -> None:
    url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
    rows = httpx.get(url, timeout=60).json()["rows"][:n]
    names = sorted({r["project"].lower() for r in rows})
    (OUT / "pypi_top.txt").write_text("\n".join(names), encoding="utf-8")
    print(f"pypi_top.txt: {len(names)} packages")


def npm(n: int = 8000) -> None:
    names: set[str] = set()
    with httpx.Client(timeout=60) as c:
        for offset in range(0, n, 250):
            r = c.get("https://registry.npmjs.org/-/v1/search",
                      params={"text": "boost-exact:false", "size": 250, "from": offset})
            if r.status_code != 200:
                break
            objs = r.json().get("objects", [])
            if not objs:
                break
            names |= {o["package"]["name"].lower() for o in objs}
    (OUT / "npm_top.txt").write_text("\n".join(sorted(names)), encoding="utf-8")
    print(f"npm_top.txt: {len(names)} packages")


if __name__ == "__main__":
    pypi()
    npm()
