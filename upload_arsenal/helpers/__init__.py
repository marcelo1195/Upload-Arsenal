"""Auxiliary field tools built on top of a generated suite.

These share the manifest (``index.json``) so that uploading payloads, catching
out-of-band callbacks and locating stored files all update one source of truth.

Tools
-----
- ``upload_arsenal.helpers.uploader``  : upload each payload at a target endpoint,
  driven by a raw ``request.txt`` copied from Burp/Caido.
- ``upload_arsenal.helpers.callback``  : HTTP (+ optional DNS) listener for
  SSRF/XXE/shell callbacks, with optional ngrok tunnelling.
- ``upload_arsenal.helpers.hunter``    : locate where an uploaded file was stored.
- ``upload_arsenal.helpers.export_req``: export each payload as a ``.req`` file
  for Burp Repeater / ffuf.
"""
