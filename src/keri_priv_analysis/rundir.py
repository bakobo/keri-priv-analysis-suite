"""Write and read a run directory's compartments and ground truth, which live apart.

Layout: ``compartments/index.json`` lists each compartment with its status, records, logs and
presentations; each CESR stream and each presentation's raw bytes is its own file beside it, so
the bytes an attack read can be handed to any CESR tool. ``ground-truth.json`` sits at the top.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from . import errors
from .model import Compartment, CompartmentSet, GroundTruth, Knowledge, LogLine, Presentation


def _dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=1, sort_keys=True) + "\n")


def write_compartments(run: Path, compartments: CompartmentSet) -> None:
    base = Path(run) / "compartments"
    (base / "streams").mkdir(parents=True, exist_ok=True)
    index = []
    for n, c in enumerate(compartments):
        streams = {}
        for m, (name, data) in enumerate(c.streams.items()):
            filename = f"streams/{n}-{m}.cesr"
            (base / filename).write_bytes(data)
            streams[name] = filename
        index.append({
            "name": c.name,
            "status": c.status,
            "note": c.note,
            "streams": streams,
            "records": c.records,
            "logs": [[line.time, line.source, line.text] for line in c.logs],
            "presentations": [
                {**{k: v for k, v in vars(p).items() if k != "raw"},
                 "raw": base64.b64encode(p.raw).decode()}
                for p in c.presentations
            ],
        })
    _dump(base / "index.json", index)


def read_compartments(run: Path) -> CompartmentSet:
    base = Path(run) / "compartments"
    if not (base / "index.json").is_file():
        raise errors.RUN_COMPARTMENTS_MISSING(path=str(run))
    out = []
    for entry in json.loads((base / "index.json").read_text()):
        out.append(Compartment(
            name=entry["name"],
            status=entry["status"],
            note=entry["note"],
            streams={k: (base / v).read_bytes() for k, v in entry["streams"].items()},
            records=entry["records"],
            logs=[LogLine(*line) for line in entry["logs"]],
            presentations=[
                Presentation(**{**p, "raw": base64.b64decode(p["raw"])})
                for p in entry["presentations"]
            ],
        ))
    return CompartmentSet(out)


def write_ground_truth(run: Path, truth: GroundTruth) -> None:
    _dump(Path(run) / "ground-truth.json", vars(truth))


def read_ground_truth(run: Path) -> GroundTruth:
    return GroundTruth(**json.loads((Path(run) / "ground-truth.json").read_text()))


def write_knowledge(run: Path, knowledge: Knowledge) -> None:
    _dump(Path(run) / "knowledge.json", vars(knowledge))


def read_knowledge(run: Path) -> Knowledge:
    return Knowledge(**json.loads((Path(run) / "knowledge.json").read_text()))
