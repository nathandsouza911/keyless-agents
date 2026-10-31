"""The fictional tenant's fake Graph, for the e2e stack. It lives in clw.demo.fake_graph,
shared with the quick start (SD-051); this module keeps the e2e compose's `fake_graph:app`."""

from clw.demo.fake_graph import *  # noqa: F401,F403
from clw.demo.fake_graph import app, create_app  # noqa: F401
