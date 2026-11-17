# The documentation site

The suite's documentation and its scored results are published at <https://bakobo.github.io/keri-priv-analysis-suite/>. The site is built the same way as the [KERI conformance suite's](https://bakobo.github.io/keri-conformance-suite/), with the same theme, so the two read as one family.

## What it publishes

The site carries the README as its home page, every file under `docs/`, and the files under `results/` that a reader reads rather than parses: each run's `report.md`, the sweep summary and its plot. Every other file in the repository that a page links to, such as a `results.json`, a scenario or the raw-export manifest, is linked on GitHub instead.

The site renders only what is committed. It runs no scenario and no adapter, and it does not render results itself: each run's `report.md` is the one `kpa report` wrote from that run's `results.json`, so the site cannot disagree with the report a reader would regenerate. A push to `main` that changes markdown or results republishes the site without re-analysing anything.

## What the build refuses

`scripts/site-source` assembles the site's markdown into `_site/src` and rewrites each link for that layout. It stops, and the site is not built, when:

- a page links to a path the repository does not have, or to one outside it, or the link goes through a symbolic link;
- a published page, rendered with the site's own markdown extensions, contains an element, an attribute or a link scheme outside a short allow-list (the elements markdown produces, no event handlers, inline style only for table alignment, and links that are relative or use `http`, `https` or `mailto`);
- a published SVG does not parse, declares entities, or holds a script, an animation or `foreignObject` element, an event handler, a link with any other scheme, or CSS that loads from elsewhere (`@import`, or a `url()` that is not a `#` reference), whatever namespace prefix it uses;
- a file under `docs/` would take the place of a generated page (`docs/index.md` or `docs/results/`);
- the output directory exists and the tool did not make it.

The HTML rules exist because a report can carry text an adapter supplied, such as the owner of a failed claim. A report that put markup there would otherwise publish it on this site's origin. The rule refuses the report rather than escaping it, so a committed report and its published page always say the same thing. The check renders the page instead of searching the markdown for tags, because markdown has too many ways to produce markup that a pattern over the source misses: escaped backticks that look like a code span, a fence indented far enough to be ordinary text, `attr_list` attributes and `javascript:` links all got past the first version. The renderer is the Python-Markdown and pymdown-extensions versions that the pinned Zensical uses, and a test holds the extension list to `zensical.toml`.

## Building it locally

```bash
uv sync --locked --group site
uv run python scripts/site-source
uv run zensical build --clean --strict
```

The site is then in `_site/html`, which `python3 -m http.server --directory _site/html` serves. Zensical is pre-1.0, so `pyproject.toml` pins it exactly and a newer version is adopted by changing the pin. Its only input is the plain markdown in `_site/src`, so replacing the generator means replacing `zensical.toml` and one build step.

## Deployment

`.github/workflows/pages.yml` runs on every push to `main`. Its build job holds a read-only token. Its deploy job holds the Pages and OIDC permissions and runs no repository code. CI's `site` job builds the same site on every pull request without deploying it, so a broken link fails the pull request rather than the deploy. Pages must be enabled in the repository's settings with GitHub Actions as its source. Otherwise the deploy job stops at its configuration check.
