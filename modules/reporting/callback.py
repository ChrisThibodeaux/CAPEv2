import os
import logging
import requests

from requests.exceptions import Timeout, RequestException
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.core.database import TASK_REPORTED, Database

TIMEOUT = 300

log = logging.getLogger(__name__)
main_db = Database()


class CALLBACKHOME(Report):
    "Notify us about analysis is done"

    order = 10000  # used in the reporting module and required here.

    def run(self, results):
        task_id = self.task["id"]
        username = self.task["username"]
        filename = results.get("target", {}).get("file", {}).get("sha256", {})

        if username is None:  # If the file was uploaded form the UC dashboard
            log.warning("Unable to gather username. Callback upload to Unknowncyber failed")
            return

        """
        Handles a possible race condition where the status is not updated before the callback is consumed.
        """
        # set completed_on time
        with Database().session.begin():
            Database().set_status(task_id, TASK_REPORTED)

        file_data = {}
        body = {}
        request_headers = {}

        binary_link = os.path.join(self.analysis_path, "binary")
        file_sample_path = os.path.realpath(binary_link)





        params = {
            "no_links": True,
            "uri": False,
            "retain_wrapper": True,
            "extract": True,
            "seen_sandbox": True,  #  Prevent UC API from resubmitting file to the sandbox 
        }

        # Only open the file when ready to send the request
        with open(file_sample_path, 'rb') as f:
            file_data["filedata"] = (filename, f, "application/octet-stream")
            try:
                requests.post(
                    url="https://api.magic.unknowncyber.com/v2/files/",
                    params=params,
                    headers=request_headers,
                    data=body,
                    files=file_data,
                    timeout=TIMEOUT,
                )
            except Timeout as e:
                log.error(f"Callback upload failed from timeout: {e}")
            except RequestException as e:
                log.error("Callback upload failed.")
                log.error(repr(e), exc_info=True)
