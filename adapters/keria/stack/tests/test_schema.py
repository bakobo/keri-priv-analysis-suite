import json
import urllib.error
import urllib.request

import pytest
from keri.core import coring

from kpa_keria_stack import schema


def test_build_is_saidified_and_names_the_attributes():
    built = schema.build(["age-band", "county"])
    said = built["$id"]
    assert said and coring.Saider(qb64=said).verify(built, prefixed=True,
                                                     label=coring.Saids.dollar)
    attrs = built["properties"]["a"]["oneOf"][1]
    assert attrs["required"] == ["d", "i", "dt", "age-band", "county"]
    assert schema.build(["age-band", "county"]) == built


def test_server_serves_the_schema_and_nothing_else():
    built = schema.build(["age-band"])
    with schema.Server(built) as server:
        assert server.oobi.endswith(f"/oobi/{built['$id']}")
        with urllib.request.urlopen(server.oobi) as response:
            assert response.headers["Content-Type"] == "application/schema+json"
            assert json.loads(response.read()) == built
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(server.oobi.replace(built["$id"], "nothing"))
        assert exc.value.code == 404
