"""Every error the KERIA adapter raises itself, declared once at module scope
(dev/standards/error-codes.md). Refusing a stack setting uses the suite's ADAPTER_SETTING."""

from bakobo.errors import ErrorCode

STACK_FAILED = ErrorCode(
    "e.env.keria.driver.r",
    "The KERIA stack did not complete the scenario.",
    detail="The KERIA driver exited with code {code}. The last of what it wrote: {tail}",
    args=("code", "tail"),
    hint="Run `uv sync --locked` in adapters/keria/stack, then try again; the driver's output "
    "names the step that failed.",
)
UV_MISSING = ErrorCode(
    "e.env.keria.uv.f",
    "uv, which runs the KERIA stack's own environment, is not installed.",
    detail="The adapter runs KERIA in adapters/keria/stack with `uv run`, and no uv is on PATH.",
    hint="Install uv (https://docs.astral.sh/uv/) and run `uv sync --locked` in "
    "adapters/keria/stack.",
)
