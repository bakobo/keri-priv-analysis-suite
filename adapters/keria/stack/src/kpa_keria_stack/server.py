"""Run one KERIA agency in this process, as `python -m kpa_keria_stack.server`.

The driver starts one of these per access boundary (the State's issuing homes, the citizens' wallet
host, each verifier), each with its own HOME, keystore directory, config and ports. It logs every
HTTP request at INFO, which is KERIA's own `--logrequests` behaviour, to standard error, which the
driver captures as that host's log. Adapted from SignifyPy's integration harness,
tests/integration/_services/keria_server.py at 2e9772cb.
"""

from __future__ import annotations

import argparse
import signal


def config(args):
    from keria.app import agenting

    return agenting.KERIAServerConfig(
        name="keria", base="", adminPort=args.admin_port, httpPort=args.http_port,
        bootPort=args.boot_port, configFile="kpa", configDir=args.config_dir, logLevel="INFO",
        logRequests=True, releaseTimeout=86400)


def contain(data_dir: str) -> None:
    """Keep every store and log this agency writes under data_dir.

    keripy and hio default to /usr/local/var/keri whenever it is writable, a directory every KERI
    process on the machine shares, and KERIA offers no option to move it. Setting the class
    defaults moves where the files live without changing what KERIA writes.
    """
    from hio.base import filing
    from hio.help import ogling
    from keri.db import dbing

    for cls in (dbing.LMDBer, filing.Filer, ogling.Ogler):
        cls.HeadDirPath = data_dir
        cls.AltHeadDirPath = data_dir
    ogling.Ogler.TempHeadDir = data_dir


def _stop(*_):
    raise KeyboardInterrupt


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", required=True)
    parser.add_argument("--admin-port", required=True, type=int)
    parser.add_argument("--http-port", required=True, type=int)
    parser.add_argument("--boot-port", required=True, type=int)
    parser.add_argument("--data-dir", required=True)
    args = parser.parse_args(argv)
    contain(args.data_dir)
    from keria.app import agenting

    signal.signal(signal.SIGTERM, _stop)
    try:
        agenting.runAgency(config=config(args), temp=False)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
