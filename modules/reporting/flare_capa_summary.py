# Copyright (C) 2019-2024 DoomedRaven
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.integrations.capa import HAVE_FLARE_CAPA, flare_capa_details

log = logging.getLogger(__name__)


def generate_cape_analysis_summary(results):
    if not results.get("target"):
        return {}
    try:
        return flare_capa_details(results["target"]["file"]["path"], "static", on_demand=True, backend="cape", results=results)
    except Exception as e:
        log.warning(f"Can't generate FLARE CAPA: {e}")

    return {}


class CAPASummary(Report):
    """Generate CAPE analysis summary by using FLARE CAPA"""

    def run(self, results):
        if HAVE_FLARE_CAPA and self.options.enabled and not self.options.on_demand:
            report = generate_cape_analysis_summary(results)
            if report:
                results["capa_summary"] = report
