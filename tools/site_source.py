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
claim's owner, say), so each published page is rendered here with the site's own markdown
extensions and refused unless every element, attribute and URL scheme in the result is on a short
allow-list, and each published SVG is parsed and refused if it holds anything that can run. Both
checks read what a browser would get rather than patterns in the source, because the source-level
version missed escaped backticks, indented fences, attr_list attributes and javascript: links
(the hostile pass on #7). The output is the same bytes for the same tree.
"""

import argparse
import html.parser
import os
import posixpath
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import markdown
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
    "A published page would render markup outside the site's allow-list.",
    detail="{where} renders to {snippet}, which is not an element, attribute or link the site "
    "publishes. Pages are held to a short allow-list so that text an adapter supplied can never "
    "become active markup on the site.",
    args=("where", "snippet"),
    hint="Put raw HTML in backticks, drop the attribute list, or link with http, https or mailto.",
)
SITE_SVG = ErrorCode(
    "e.rule.markup.site-svg-active.f",
    "A published SVG carries something that can run code.",
    detail="{where} contains {snippet}. A published SVG may hold only drawing.",
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
# A fence opens with at most three spaces of indent (four make indented code instead) and three or
# more of one character, and closes only on a run of the same character at least as long with
# nothing after it, as in CommonMark.
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")


def _lines_outside_fences(text: str):
    """Each line of the markdown `text` with its number and whether it is in a fenced code block."""
    opener = None
    for number, line in enumerate(text.splitlines(keepends=True), start=1):
        match = _FENCE.match(line.rstrip("\r\n"))
        # A backtick fence's info string may not hold a backtick; such a line is inline code.
        if opener is None and match and not (match.group(1)[0] == "`" and "`" in match.group(2)):
            opener = match.group(1)
            yield number, line, True
        elif opener is not None:
            closes = (match is not None and match.group(1)[0] == opener[0]
                      and len(match.group(1)) >= len(opener) and not match.group(2).strip())
            if closes:
                opener = None
            yield number, line, True
        else:
            yield number, line, False


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


def rewrite_links(text: str, source: str, target: str, repo) -> str:
    """Rewrite the inline links and images in the markdown `text`, a file at repository path
    `source` that will live at `target` in the site source. Fenced code blocks are left as they
    are."""
    repo = Path(repo)
    out = []
    for number, line, fenced in _lines_outside_fences(text):
        if not fenced:
            def link(m, where=f"{source}:{number}"):
                return f"]({_rewrite_target(m.group(1), source, target, repo, where)}{m.group(2)})"

            line = _LINK.sub(link, line)
        out.append(line)
    return "".join(out)


# The markdown extensions the site renders with, as zensical.toml configures them; a test holds the
# two together.
EXTENSIONS = {
    "admonition": {},
    "attr_list": {},
    "tables": {},
    "toc": {"permalink": True},
    "pymdownx.highlight": {"anchor_linenums": True},
    "pymdownx.superfences": {},
}
# What a rendered page may contain. Everything else is refused rather than escaped, so a committed
# report and its published page always say the same thing.
_ALLOWED_TAGS = frozenset({
    "a", "abbr", "blockquote", "br", "code", "dd", "del", "details", "div", "dl", "dt", "em",
    "h1", "h2", "h3", "h4", "h5", "h6", "hr", "img", "li", "ol", "p", "pre", "span", "strong",
    "sub", "summary", "sup", "table", "tbody", "td", "th", "thead", "tr", "ul",
})
_ALLOWED_ATTRS = frozenset({
    "href", "src", "alt", "title", "class", "id", "name", "style", "colspan", "rowspan", "open",
})
_URL_ATTRS = frozenset({"href", "src"})
_SAFE_SCHEMES = frozenset({"http", "https", "mailto"})
_TABLE_ALIGN = re.compile(r"text-align:\s*(left|right|center);?")
_URL_SCHEME = re.compile(r"^([a-z][a-z0-9+.-]*):")
_STRIP = re.compile(r"[\x00-\x20\x7f]")


def _scheme(url: str) -> str | None:
    """The scheme a browser would read from `url`, which ignores ASCII whitespace and control
    characters and case, or None for a relative URL."""
    match = _URL_SCHEME.match(_STRIP.sub("", url).lower())
    return match.group(1) if match else None


class _Inspector(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.refused: str | None = None

    def _refuse(self, what: str) -> None:
        if self.refused is None:
            self.refused = what

    def handle_starttag(self, tag, attrs) -> None:
        if tag not in _ALLOWED_TAGS:
            self._refuse(f"a <{tag}> element")
        for name, value in attrs:
            value = value or ""
            if name not in _ALLOWED_ATTRS:
                self._refuse(f"a {name} attribute on <{tag}>")
            elif name == "style" and not _TABLE_ALIGN.fullmatch(value.strip()):
                self._refuse(f"a style attribute {value!r} on <{tag}>")
            elif name in _URL_ATTRS and _scheme(value) not in (None, *_SAFE_SCHEMES):
                self._refuse(f"a {_scheme(value)}: URL in {name} on <{tag}>")

    def handle_comment(self, data) -> None:
        self._refuse("an HTML comment")

    def handle_decl(self, decl) -> None:
        self._refuse("a markup declaration")

    def handle_pi(self, data) -> None:
        self._refuse("a processing instruction")

    def unknown_decl(self, data) -> None:
        self._refuse("a markup declaration")


def check_markup(text: str, source: str) -> None:
    """Refuse the markdown `text` unless it renders, with the site's extensions, to allowed
    elements and attributes only, linking with no scheme or http, https or mailto."""
    rendered = markdown.markdown(text, extensions=list(EXTENSIONS),
                                 extension_configs=EXTENSIONS)
    inspector = _Inspector()
    inspector.feed(rendered)
    inspector.close()
    if inspector.refused is not None:
        raise SITE_HTML(where=source, snippet=inspector.refused)


# What a published SVG may contain, by local name, lowercased: the drawing vocabulary a plotting
# library writes, and nothing that can run, animate, embed or fetch. An allow-list, because each
# list of things to refuse that was tried here (#7) was outrun by another spelling.
_SVG_ELEMENTS = frozenset({
    "svg", "g", "defs", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
    "text", "tspan", "clippath", "use", "style", "title", "desc", "lineargradient",
    "radialgradient", "stop", "metadata", "rdf", "work", "agent", "creator", "format", "type",
    "date", "description",
})
_SVG_ATTRIBUTES = frozenset({
    "id", "class", "style", "transform", "d", "x", "y", "width", "height", "viewbox", "version",
    "preserveaspectratio", "href", "clip-path", "clippathunits", "fill", "fill-opacity",
    "fill-rule", "clip-rule", "stroke", "stroke-width", "stroke-opacity", "stroke-linecap",
    "stroke-linejoin", "stroke-dasharray", "stroke-dashoffset", "stroke-miterlimit", "opacity",
    "points", "cx", "cy", "r", "rx", "ry", "x1", "y1", "x2", "y2", "dx", "dy", "font-family",
    "font-size", "font-weight", "font-style", "text-anchor", "dominant-baseline", "offset",
    "stop-color", "stop-opacity", "gradientunits", "gradienttransform", "space", "resource", "type",
})
# CSS may reference only this document: no backslash, which CSS reads as an escape that can spell
# any word; no at-rule; and no url() other than a # reference.
_UNSAFE_CSS = re.compile(r"\\|@|url\(\s*(?!\s|['\"]?\s*#)", re.IGNORECASE)
# matplotlib writes an external DOCTYPE, which declares nothing; an entity or an internal subset
# could define text the parser would substitute.
_DECLARATION = re.compile(r"<!ENTITY|<!DOCTYPE[^>]*\[", re.IGNORECASE)
_XML_DECLARATION = re.compile(r"\s*<\?xml\s[^?]*\?>")


def _local(name: str) -> str:
    return name.rpartition("}")[2].rpartition(":")[2].lower()


def check_svg(svg: str, source: str) -> None:
    """Refuse an SVG that is not well-formed, declares entities or an internal DTD subset, carries
    a processing instruction other than the XML declaration, or holds an element or attribute off
    the allow-list, a link other than a # reference, or CSS that could load from elsewhere. Names
    are compared by local name, so a namespace prefix hides nothing."""
    if _DECLARATION.search(svg):
        raise SITE_SVG(where=source, snippet="an entity declaration or internal DTD subset")
    declaration = _XML_DECLARATION.match(svg)
    if "<?" in svg[declaration.end() if declaration else 0:]:
        raise SITE_SVG(where=source, snippet="a processing instruction")
    try:
        root = ET.fromstring(svg)
    except ET.ParseError as exc:
        raise SITE_SVG(where=source, snippet=f"XML that does not parse ({exc})") from None
    for element in root.iter():
        tag = _local(element.tag)
        if tag not in _SVG_ELEMENTS:
            raise SITE_SVG(where=source, snippet=f"a <{tag}> element")
        if tag == "style" and _UNSAFE_CSS.search(element.text or ""):
            raise SITE_SVG(where=source, snippet="a stylesheet that could load from elsewhere")
        for name, value in element.attrib.items():
            attr = _local(name)
            if attr not in _SVG_ATTRIBUTES:
                raise SITE_SVG(where=source, snippet=f"a {attr} attribute")
            if attr == "href" and not value.startswith("#"):
                raise SITE_SVG(where=source, snippet=f"a link to {value[:60]!r}")
            if attr != "resource" and _UNSAFE_CSS.search(value):
                raise SITE_SVG(where=source,
                               snippet=f"a {attr} attribute that could load from elsewhere")


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
        page = rewrite_links(path.read_text(encoding="utf-8"), source, target, repo)
        check_markup(page, source)
        destination.write_text(page, encoding="utf-8")
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
