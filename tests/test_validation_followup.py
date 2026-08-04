# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ast
from pathlib import Path


CONNECTOR = Path(__file__).parents[1] / "mssentinel_connector.py"
SOURCE = CONNECTOR.read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


def _function_source(name: str) -> str:
    node = next(item for item in ast.walk(TREE) if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name)
    return ast.get_source_segment(SOURCE, node) or ""


def test_shared_path_encoder_does_not_leave_literal_dots():
    source = _function_source("_quote_path_segment")

    assert 'quote(str(value), safe="").replace(".", "%2E")' in source


def test_action_boundary_rejects_exact_dot_incident_identifiers():
    source = _function_source("handle_action")

    assert 'str(param["incident_name"]).strip() in {".", ".."}' in source
    assert "Parameter 'incident_name' must identify one incident" in source
