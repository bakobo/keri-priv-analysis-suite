"""The documentation site's source assembly (tools/site_source.py, this.i 4vdpvhcz)."""

from pathlib import Path

import pytest
from bakobo.errors import BakoboError

from tools import site_source
from tools.site_source import REPO_URL, assemble, check_markup, check_svg, main, rewrite_links

REPO = Path(__file__).resolve().parent.parent


def _repo(tmp_path: Path) -> Path:
    """A small repository with the shape the site reads: a README, docs/, results/ and one file
    the site does not publish."""
    repo = tmp_path / "repo"
    (repo / "docs" / "stylesheets").mkdir(parents=True)
    (repo / "results" / "run-a").mkdir(parents=True)
    (repo / "results" / "sweep" / "scenarios").mkdir(parents=True)
    (repo / "scenarios").mkdir()
    (repo / "README.md").write_text(
        "# Suite\n\nSee [findings](docs/findings.md#at-a-glance), [the plan](docs/plan.md), "
        "[a scenario](scenarios/smoke.toml) and [the licence](LICENSE).\n")
    (repo / "LICENSE").write_text("licence\n")
    (repo / "scenarios" / "smoke.toml").write_text("x = 1\n")
    (repo / "docs" / "findings.md").write_text(
        "# Findings\n\n[Run A](../results/run-a/report.md), [its JSON](../results/run-a/results.json),"
        " [the sweep](../results/sweep/README.md), [home](../README.md) and [plan](plan.md).\n")
    (repo / "docs" / "plan.md").write_text("# Plan\n\n```\n[not a link](nowhere.md)\n```\n")
    (repo / "docs" / "stylesheets" / "site.css").write_text("a { color: red; }\n")
    (repo / "results" / "run-a" / "report.md").write_text(
        "# Report\n\nScenario [file](../../scenarios/smoke.toml).\n")
    (repo / "results" / "run-a" / "results.json").write_text("{}\n")
    (repo / "results" / "sweep" / "README.md").write_text(
        "# Sweep\n\n[Scenarios](scenarios/), [plot](plot.svg), [baseline](../run-a/report.md).\n\n"
        "![plot](plot.svg)\n")
    (repo / "results" / "sweep" / "scenarios" / "a.toml").write_text("x = 2\n")
    (repo / "results" / "sweep" / "plot.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"/>\n')
    (repo / "results" / "sweep" / "plot.png").write_bytes(b"\x89PNG")
    (repo / "results" / "hashes.sha256").write_text("abc  x\n")
    return repo


# Link rewriting


def test_a_docs_link_from_the_readme_points_at_the_page_beside_the_home_page(tmp_path):
    repo = _repo(tmp_path)
    out = rewrite_links("[a](docs/plan.md#part-b)", "README.md", "index.md", repo)
    assert out == "[a](plan.md#part-b)"


def test_a_link_to_the_readme_points_at_the_home_page(tmp_path):
    repo = _repo(tmp_path)
    assert rewrite_links("[h](../README.md)", "docs/plan.md", "plan.md", repo) == "[h](index.md)"


def test_a_published_results_file_keeps_its_place_under_results(tmp_path):
    repo = _repo(tmp_path)
    out = rewrite_links("[r](../results/run-a/report.md) ![p](../results/sweep/plot.svg)",
                        "docs/findings.md", "findings.md", repo)
    assert out == "[r](results/run-a/report.md) ![p](results/sweep/plot.svg)"


def test_a_link_between_results_pages_stays_relative(tmp_path):
    repo = _repo(tmp_path)
    out = rewrite_links("[b](../run-a/report.md)", "results/sweep/README.md",
                        "results/sweep/README.md", repo)
    assert out == "[b](../run-a/report.md)"


def test_an_unpublished_file_points_at_github(tmp_path):
    repo = _repo(tmp_path)
    out = rewrite_links("[j](../results/run-a/results.json)", "docs/findings.md", "findings.md",
                        repo)
    assert out == f"[j]({REPO_URL}/blob/main/results/run-a/results.json)"


def test_a_directory_points_at_its_github_tree(tmp_path):
    repo = _repo(tmp_path)
    out = rewrite_links("[s](scenarios/)", "results/sweep/README.md", "results/sweep/README.md",
                        repo)
    assert out == f"[s]({REPO_URL}/tree/main/results/sweep/scenarios)"


def test_a_fragment_survives_a_github_link(tmp_path):
    repo = _repo(tmp_path)
    out = rewrite_links("[l](LICENSE#top)", "README.md", "index.md", repo)
    assert out == f"[l]({REPO_URL}/blob/main/LICENSE#top)"


@pytest.mark.parametrize("url", ["https://example.com/x", "#local", "/abs", "mailto:a@b.c"])
def test_absolute_and_in_page_links_are_left_alone(tmp_path, url):
    repo = _repo(tmp_path)
    assert rewrite_links(f"[x]({url})", "README.md", "index.md", repo) == f"[x]({url})"


def test_a_link_title_is_kept(tmp_path):
    repo = _repo(tmp_path)
    out = rewrite_links('[a](docs/plan.md "The plan")', "README.md", "index.md", repo)
    assert out == '[a](plan.md "The plan")'


def test_a_link_inside_a_fenced_block_is_left_alone(tmp_path):
    repo = _repo(tmp_path)
    text = "```\n[x](missing.md)\n```\n[y](docs/plan.md)\n"
    assert rewrite_links(text, "README.md", "index.md", repo) == (
        "```\n[x](missing.md)\n```\n[y](plan.md)\n")


@pytest.mark.parametrize("text", [
    "```\n~~~\n```\n[x](missing.md)\n",
    "````\n```\n````\n[x](missing.md)\n",
    "~~~\n```python\n~~~\n[x](missing.md)\n",
])
def test_a_fence_closes_only_on_its_own_marker(tmp_path, text):
    """A fence of the other character, or a shorter one, is code inside the block and does not
    close it, so the link after the real close is still checked (Copilot on #7)."""
    repo = _repo(tmp_path)
    with pytest.raises(BakoboError) as err:
        rewrite_links(text, "README.md", "index.md", repo)
    assert err.value.code == site_source.SITE_LINK.code


def test_a_fence_with_an_info_string_does_not_close_a_block(tmp_path):
    repo = _repo(tmp_path)
    text = "```\n```python\n[x](missing.md)\n```\n"
    assert rewrite_links(text, "README.md", "index.md", repo) == text


def test_a_link_to_a_missing_path_is_refused(tmp_path):
    repo = _repo(tmp_path)
    with pytest.raises(BakoboError) as err:
        rewrite_links("line one\n[r](runs/)\n", "results/sweep/README.md",
                      "results/sweep/README.md", repo)
    assert err.value.code == site_source.SITE_LINK.code
    assert "results/sweep/README.md:2" in str(err.value)


def test_a_link_out_of_the_repository_is_refused(tmp_path):
    repo = _repo(tmp_path)
    (tmp_path / "outside.md").write_text("x\n")
    with pytest.raises(BakoboError) as err:
        rewrite_links("[o](../outside.md)", "README.md", "index.md", repo)
    assert err.value.code == site_source.SITE_LINK.code


# Markup checks. A page is checked as the site will render it, with the site's markdown
# extensions, so the checks see what a browser would and not a guess at it from the source.


@pytest.mark.parametrize("text", [
    "plain text with a < b and a<-arrow\n",
    "a `<dir>` in a code span\n",
    "``a <b> in a double span``\n",
    "```\n<script>in a fence</script>\n```\n",
    "an autolink <https://bakobo.github.io/x/> and <mailto:a@example.com>\n",
    "[rel](results/x.md) [abs](https://example.com/a) [frag](#here) ![img](plot.svg)\n",
    "| a | b |\n|---|---:|\n| 1 | 2 |\n",
    "!!! note\n    An admonition.\n",
    "```python\nprint(1)\n```\n",
    "## Heading {: #custom-id .some-class }\n",
])
def test_markup_that_renders_inert_passes(text):
    check_markup(text, "docs/x.md")


@pytest.mark.parametrize("text", [
    "<script>alert(1)</script>\n",
    "text <img src=x onerror=alert(1)>\n",
    "a <iframe src=x></iframe>\n",
    "a <!-- comment -->\n",
    "```\nfenced\n```\n<iframe></iframe>\n",
    # The hostile pass's inputs on #7: escaped backticks are not a code span, four spaces before
    # a fence make indented code and not a fence, attr_list writes attributes, and a link may
    # carry any scheme.
    "\\`<img src=x onerror=alert(1)>\\`\n",
    "    ```\n<img src=x onerror=alert(1)>\n",
    '![x](plot.svg){: onload="alert(1)" }\n',
    "[click](javascript:alert)\n",
    "[click](JaVa\tScript:alert)\n",
    '[x](https://example.com){: href="javascript:alert(1)" }\n',
    '[x](data:text/html,hi)\n',
    '| a |\n|---|\n| b |\n{: style="background:url(x)" }\n',
    '<p style="color: red">x</p>\n',
    "<!DOCTYPE html>\n",
    "<?php echo 1; ?>\n",
    "<![CDATA[x]]>\n",
    "<script>one</script>\n\n<iframe>two</iframe>\n",
])
def test_markup_that_could_run_code_is_refused(text):
    with pytest.raises(BakoboError) as err:
        check_markup(text, "results/r/report.md")
    assert err.value.code == site_source.SITE_HTML.code
    assert "results/r/report.md" in str(err.value)


def test_the_extensions_checked_are_the_sites():
    """check_markup renders with the extensions zensical.toml configures; a change to one without
    the other would check a page the site does not publish."""
    import tomllib

    config = tomllib.loads((REPO / "zensical.toml").read_text())["project"]["markdown_extensions"]
    names = set()
    for key, value in config.items():
        if key == "pymdownx":
            names |= {f"pymdownx.{sub}" for sub in value}
        else:
            names.add(key)
    assert names == set(site_source.EXTENSIONS)


def test_a_plain_svg_passes():
    check_svg('<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
              '<style>*{stroke-linejoin: round}</style><defs><path id="p" d="M0 0"/></defs>'
              '<use xlink:href="#p" clip-path="url(#c)" style="fill: url( \'#g\')"/></svg>',
              "results/p.svg")


@pytest.mark.parametrize("svg", [
    "<svg><script>alert(1)</script></svg>",
    '<svg xmlns="http://www.w3.org/2000/svg"><SCRIPT>x</SCRIPT></svg>',
    '<svg xmlns:s="http://www.w3.org/2000/svg"><s:script>alert(1)</s:script></svg>',
    '<svg onload="alert(1)"/>',
    '<svg xmlns:e="urn:x"><g e:onclick="alert(1)"/></svg>',
    '<svg><a href="javascript:alert(1)">x</a></svg>',
    '<svg xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:href=" JAVASCRIPT:x">x</a></svg>',
    "<svg><foreignObject><p>x</p></foreignObject></svg>",
    '<svg><set attributeName="href" to="javascript:alert(1)"/></svg>',
    '<svg><animate attributeName="href" values="javascript:alert(1)"/></svg>',
    '<!DOCTYPE svg [<!ENTITY x "y">]><svg>&x;</svg>',
    "<svg><unclosed></svg>",
    # A second reader of the fix: CSS in an SVG can load from elsewhere without a script.
    '<svg><style>@import "https://evil.example/s.css";</style></svg>',
    "<svg><style>g { fill: url( 'https://evil.example/p.svg#x' ) }</style></svg>",
    '<svg><g style="background:URL(https://evil.example/t.png)"/></svg>',
    '<svg><rect fill="url(https://evil.example/p.svg#g)"/></svg>',
])
def test_an_svg_that_can_run_code_is_refused(svg):
    with pytest.raises(BakoboError) as err:
        check_svg(svg, "results/p.svg")
    assert err.value.code == site_source.SITE_SVG.code


# Assembly


def test_assemble_lays_out_the_site_source(tmp_path):
    repo = _repo(tmp_path)
    out = tmp_path / "out"
    assemble(repo, out)
    files = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    assert files == [
        site_source.MARKER,
        "findings.md",
        "index.md",
        "plan.md",
        "results/run-a/report.md",
        "results/sweep/README.md",
        "results/sweep/plot.png",
        "results/sweep/plot.svg",
        "stylesheets/site.css",
    ]
    index = (out / "index.md").read_text()
    assert "[findings](findings.md#at-a-glance)" in index
    assert f"[a scenario]({REPO_URL}/blob/main/scenarios/smoke.toml)" in index
    report = (out / "results/run-a/report.md").read_text()
    assert f"[file]({REPO_URL}/blob/main/scenarios/smoke.toml)" in report
    assert (out / "results/sweep/plot.png").read_bytes() == b"\x89PNG"


def test_assemble_replaces_its_own_earlier_output(tmp_path):
    repo = _repo(tmp_path)
    out = tmp_path / "out"
    assemble(repo, out)
    (out / "stale.md").write_text("old\n")
    assemble(repo, out)
    assert not (out / "stale.md").exists()


def test_assemble_leaves_a_directory_it_did_not_make_alone(tmp_path):
    repo = _repo(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    (out / "keep.txt").write_text("mine\n")
    with pytest.raises(BakoboError) as err:
        assemble(repo, out)
    assert err.value.code == site_source.SITE_OUT.code
    assert (out / "keep.txt").read_text() == "mine\n"


@pytest.mark.parametrize("name", ["results", "index.md"])
def test_docs_may_not_shadow_a_generated_page(tmp_path, name):
    repo = _repo(tmp_path)
    shadow = repo / "docs" / name
    shadow.mkdir() if name == "results" else shadow.write_text("x\n")
    with pytest.raises(BakoboError) as err:
        assemble(repo, tmp_path / "out")
    assert err.value.code == site_source.SITE_COLLISION.code


def test_assemble_refuses_raw_html_in_a_report(tmp_path):
    repo = _repo(tmp_path)
    (repo / "results" / "run-a" / "report.md").write_text("Owner: <script>x</script>\n")
    with pytest.raises(BakoboError) as err:
        assemble(repo, tmp_path / "out")
    assert err.value.code == site_source.SITE_HTML.code


def test_assemble_refuses_an_active_svg(tmp_path):
    repo = _repo(tmp_path)
    (repo / "results" / "sweep" / "plot.svg").write_text("<svg onload='x'/>")
    with pytest.raises(BakoboError) as err:
        assemble(repo, tmp_path / "out")
    assert err.value.code == site_source.SITE_SVG.code


def test_assemble_refuses_a_symbolic_link(tmp_path):
    repo = _repo(tmp_path)
    (repo / "docs" / "link.md").symlink_to(repo / "docs" / "plan.md")
    with pytest.raises(BakoboError) as err:
        assemble(repo, tmp_path / "out")
    assert err.value.code == site_source.SITE_LINK.code


# Command line


def test_main_writes_the_default_output_and_reports_it(tmp_path, capsys):
    repo = _repo(tmp_path)
    assert main(["--repo", str(repo)]) == 0
    assert (repo / "_site" / "src" / "index.md").exists()
    assert str(repo / "_site" / "src") in capsys.readouterr().out


def test_main_honours_out(tmp_path):
    repo = _repo(tmp_path)
    assert main(["--repo", str(repo), "--out", str(tmp_path / "elsewhere")]) == 0
    assert (tmp_path / "elsewhere" / "index.md").exists()


def test_main_reports_a_refusal_and_fails(tmp_path, capsys):
    repo = _repo(tmp_path)
    (repo / "docs" / "plan.md").write_text("[gone](gone.md)\n")
    assert main(["--repo", str(repo), "--out", str(tmp_path / "o")]) == 1
    err = capsys.readouterr().err
    assert err.startswith("scripts/site-source: ")
    assert site_source.SITE_LINK.code in err


def test_main_refuses_an_unknown_argument(capsys):
    assert main(["--bogus"]) == 2
    err = capsys.readouterr().err
    assert site_source.SITE_ARGS.code in err
    assert "Retrying the same command will not help" in err


def test_the_real_repository_assembles(tmp_path):
    """The committed docs and results build: every link resolves and nothing carries raw HTML."""
    assemble(REPO, tmp_path / "out")
    assert (tmp_path / "out" / "index.md").exists()
    assert (tmp_path / "out" / "results" / "privacy-sweeps" / "bits-and-completeness.svg").exists()
