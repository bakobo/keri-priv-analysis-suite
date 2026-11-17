"""The documentation site's markdown source (this.i 4vdpvhcz): the README as the home page, docs/
beside it, and the committed reports, sweep summaries and plots under results/.

The site generator (Zensical, pinned in pyproject.toml's site group) reads only the tree this
writes, which is plain markdown, so replacing the generator means replacing one build step. The
tree is assembled rather than pointed at docs/ directly because the home page is the README, which
lives at the repository root, and because the results live outside docs/. Links are rewritten for
the new layout: a link to the README, to a file under docs/ or to a published results file points
at its place on the site, and a link to any other path in the repository points at it on GitHub.
A link to a path that does not exist is refused, so the site cannot publish a dead link that
GitHub's own rendering would hide until someone clicks it.

Nothing here renders results: each committed run's report.md is written by `kpa report` from its
results.json, and is published as it is. Text in a report can come from an adapter (a failed
claim's owner, say), so every published page is refused if it carries raw HTML outside code, and
every published SVG if it carries anything that can run. The output is the same bytes for the same
tree.
"""

import argparse
import os
import posixpath
import re
import shutil
import sys
from pathlib import Path

from bakobo.errors import BakoboError, ErrorCode

REPO_URL = "https://github.com/bakobo/keri-priv-analysis-suite"
MARKER = ".kpa-site-source"
RESULTS_DIR = "results"
# The results files the site carries. Everything else under results/ (results.json, report.json,
# CSV, scenario TOML, the hash manifest) is linked on GitHub.
PUBLISHED_SUFFIXES = (".md", ".svg", ".png")

SITE_OUT = ErrorCode(
    "e.state.conflict.site-source-out.f",
    "The site source's output directory was not made by this tool.",
    detail="{path} exists and was not made by scripts/site-source, so it is left alone.",
    args=("path",),
    hint="Choose another --out, or remove the directory yourself.",
)
SITE_COLLISION = ErrorCode(
    "e.self.config.site-source-collision.f",
    "A file under docs/ would take the place of a generated page.",
    detail="{path} exists, but the site's {name} is generated from elsewhere in the repository.",
    args=("path", "name"),
    hint="Move or rename it.",
)
SITE_LINK = ErrorCode(
    "e.state.missing.site-link-target.f",
    "A page links to a path the repository does not have.",
    detail="{where} links to {url}, which resolves to {path}, and that is not a file or directory "
    "in the repository (a symbolic link or a path outside the repository counts as missing).",
    args=("where", "url", "path"),
    hint="Fix the link, or commit what it points at.",
)
SITE_HTML = ErrorCode(
    "e.rule.markup.site-raw-html.f",
    "A published page carries raw HTML.",
    detail="{where} has {snippet!r} outside code. Published pages are markdown only, so text an "
    "adapter supplied can never become markup on the site.",
    args=("where", "snippet"),
    hint="Put it in backticks, or reword it without angle brackets.",
)
SITE_SVG = ErrorCode(
    "e.rule.markup.site-svg-active.f",
    "A published SVG carries something that can run code.",
    detail="{where} contains {snippet!r}. A published SVG may hold only drawing.",
    args=("where", "snippet"),
    hint="Regenerate the plot without scripts, event handlers or embedded HTML.",
)
SITE_ARGS = ErrorCode(
    "e.input.usage.site-source-args.f",
    "The command line could not be understood.",
    detail="{problem}. Retrying the same command will not help; correct the arguments.",
    args=("problem",),
)

_LINK = re.compile(r"\]\(([^()\s]+)((?:\s+\"[^\"]*\")?)\)")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_FENCE = re.compile(r"^\s*(```|~~~)")
_CODE_SPAN = re.compile(r"(`+)(?:(?!\1).)+?\1")
_AUTOLINK = re.compile(r"<(?:https?|mailto):[^<>\s]+>")
_TAG = re.compile(r"<[A-Za-z!/?][^>\n]{0,40}")
_ACTIVE_SVG = re.compile(r"<script|<foreignobject|\son[a-z]+\s*=|javascript:", re.IGNORECASE)


def _lines_outside_fences(markdown: str):
    """Each line of `markdown` with its number and whether it is inside a fenced code block."""
    fenced = False
    for number, line in enumerate(markdown.splitlines(keepends=True), start=1):
        if _FENCE.match(line):
            fenced = not fenced
            yield number, line, True
        else:
            yield number, line, fenced


def _site_path(resolved: str) -> str | None:
    """Where the repository path `resolved` lives on the site, or None if the site does not carry
    it."""
    if resolved == "README.md":
        return "index.md"
    if resolved.startswith("docs/"):
        return resolved[len("docs/"):]
    if resolved.startswith(RESULTS_DIR + "/") and resolved.endswith(PUBLISHED_SUFFIXES):
        return resolved
    return None


def _rewrite_target(url: str, source: str, target: str, repo: Path, where: str) -> str:
    if url.startswith(("#", "/")) or _SCHEME.match(url):
        return url
    path, hash_, fragment = url.partition("#")
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(source), path))
    full = repo / resolved
    if resolved.startswith("../") or resolved == ".." or full.is_symlink() or not full.exists():
        raise SITE_LINK(where=where, url=url, path=resolved)
    new = _site_path(resolved)
    if new is None:
        kind = "tree" if full.is_dir() else "blob"
        return f"{REPO_URL}/{kind}/main/{resolved}{hash_}{fragment}"
    start = posixpath.dirname(target) or "."
    return posixpath.relpath(new, start) + hash_ + fragment


def rewrite_links(markdown: str, source: str, target: str, repo) -> str:
    """Rewrite the inline links and images in `markdown`, a file at repository path `source` that
    will live at `target` in the site source. Fenced code blocks are left as they are."""
    repo = Path(repo)
    out = []
    for number, line, fenced in _lines_outside_fences(markdown):
        if not fenced:
            def link(m, where=f"{source}:{number}"):
                return f"]({_rewrite_target(m.group(1), source, target, repo, where)}{m.group(2)})"

            line = _LINK.sub(link, line)
        out.append(line)
    return "".join(out)


def check_markup(markdown: str, source: str) -> None:
    """Refuse `markdown` if it has raw HTML outside fenced blocks, code spans and autolinks."""
    for number, line, fenced in _lines_outside_fences(markdown):
        if fenced:
            continue
        bare = _AUTOLINK.sub("", _CODE_SPAN.sub("", line))
        match = _TAG.search(bare)
        if match:
            raise SITE_HTML(where=f"{source}:{number}", snippet=match.group(0))


def check_svg(svg: str, source: str) -> None:
    """Refuse an SVG that carries a script, an event handler, a javascript: URL or embedded
    HTML."""
    match = _ACTIVE_SVG.search(svg)
    if match:
        raise SITE_SVG(where=source, snippet=match.group(0))


def _files(root: Path, repo: Path):
    """Every file under `root`, sorted, refusing a symbolic link."""
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(repo).as_posix()
        if path.is_symlink():
            raise SITE_LINK(where=relative, url=relative, path=relative)
        if path.is_file():
            yield path, relative


def _publish(path: Path, source: str, target: str, out: Path, repo: Path) -> None:
    destination = out / target
    destination.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".md":
        markdown = path.read_text(encoding="utf-8")
        check_markup(markdown, source)
        destination.write_text(rewrite_links(markdown, source, target, repo), encoding="utf-8")
        return
    if path.suffix == ".svg":
        check_svg(path.read_text(encoding="utf-8"), source)
    shutil.copyfile(path, destination)


def assemble(repo, out) -> None:
    """Write the site source for the repository at `repo` into `out`, replacing what a previous
    run wrote there. A directory this did not make is refused, never emptied."""
    repo, out = Path(repo), Path(out)
    docs = repo / "docs"
    for name in (RESULTS_DIR, "index.md"):
        if (docs / name).exists():
            raise SITE_COLLISION(path=docs / name, name=name)
    if out.exists():
        if not (out / MARKER).exists():
            raise SITE_OUT(path=out)
        shutil.rmtree(out)
    out.mkdir(parents=True)
    (out / MARKER).write_text("Written by tools/site_source.py; safe to delete.\n")
    for path, source in _files(docs, repo):
        _publish(path, source, source[len("docs/"):], out, repo)
    _publish(repo / "README.md", "README.md", "index.md", out, repo)
    for path, source in _files(repo / RESULTS_DIR, repo):
        if source.endswith(PUBLISHED_SUFFIXES):
            _publish(path, source, source, out, repo)


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _UsageError(message)


def main(argv: list[str] | None = None) -> int:
    repo_default = Path(__file__).resolve().parent.parent
    parser = _Parser(prog="scripts/site-source",
                     description="Assemble the documentation site's markdown source.")
    parser.add_argument("--repo", default=str(repo_default), help="the repository root")
    parser.add_argument("--out", default=None, help="where to write (default: REPO/_site/src)")
    try:
        args = parser.parse_args(argv)
    except _UsageError as exc:
        print(f"scripts/site-source: {SITE_ARGS(problem=str(exc))}", file=sys.stderr)
        return 2
    repo = Path(args.repo)
    out = Path(args.out) if args.out else repo / "_site" / "src"
    try:
        assemble(repo, out)
    except BakoboError as exc:
        print(f"scripts/site-source: {exc}", file=sys.stderr)
        return 1
    print(f"wrote the site source to {os.fspath(out)}")
    return 0
