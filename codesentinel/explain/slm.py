"""Optional local rephrasing. Off by default; never introduces a claim.

The model receives the template text and the user's own code, and may only
rewrite for that context. If it is unavailable, the template ships unchanged -
which is why the product works with no model at all.
"""
from __future__ import annotations

import os

SYSTEM = (
    "You rewrite a fixed security explanation so it refers to the user's own "
    "variable and function names. Rules: do not add any claim not present in the "
    "input; do not change the CWE; do not invent code. If you cannot improve it, "
    "return the input unchanged."
)


def rephrase(explanation: str, code: str) -> str:
    if os.environ.get("CS_ENABLE_SLM") != "1":
        return explanation
    try:
        from llama_cpp import Llama          # optional dependency

        llm = Llama(model_path=os.environ["CS_SLM_PATH"], n_ctx=2048, verbose=False)
        out = llm.create_chat_completion(
            messages=[{"role": "system", "content": SYSTEM},
                      {"role": "user",
                       "content": f"CODE:\n{code[:1500]}\n\nTEXT:\n{explanation}"}],
            max_tokens=280, temperature=0.2,
        )
        return out["choices"][0]["message"]["content"].strip() or explanation
    except Exception:                        # noqa: BLE001
        return explanation                   # never fail a scan because of the model
