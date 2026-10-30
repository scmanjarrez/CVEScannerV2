# SPDX-License-Identifier: GPL-3.0-or-later

"""Frozen copy of the pre-optimisation CPE parser.

Keep this module byte-for-byte equivalent to the original algorithm so that
optimised implementations can be compared against it. Do not import helpers
from db_manager.domain.cpe here, because the reference must not change when
the production parser changes.
"""

import re

from db_manager.constants import MIN_CPE_COMPONENTS
from db_manager.domain.models import CpeIdentity


def _reference_unescape(value: str) -> str:
    """Remove CPE escape markers from one parsed component.

    Args:
        value: CPE component with formatted-string escape markers.

    Returns:
        The component with escaped characters decoded.
    """
    return re.sub(r"\\(.)", r"\1", value)


def _reference_split_components(cpe_uri: str) -> list[str]:
    """Split a CPE name while preserving escaped colons within fields.

    Args:
        cpe_uri: Formatted CPE 2.2 or 2.3 name.

    Returns:
        Decoded CPE fields after the CPE scheme and version prefix.

    Raises:
        ValueError: If the CPE scheme is unsupported or fields are incomplete.
    """
    if cpe_uri.startswith("cpe:2.3:"):
        value = cpe_uri[len("cpe:2.3:") :]
    elif cpe_uri.startswith("cpe:/"):
        value = cpe_uri[len("cpe:/") :]
    else:
        message = f"Unsupported CPE name: {cpe_uri}"
        raise ValueError(message)

    components: list[str] = []
    component: list[str] = []
    escaped = False
    for char in value:
        if char == ":" and not escaped:
            components.append("".join(component))
            component = []
            continue
        component.append(char)
        escaped = char == "\\" and not escaped
    components.append("".join(component))

    if value.startswith("/") and components:
        components[0] = components[0][1:]
    if len(components) < MIN_CPE_COMPONENTS:
        message = f"Incomplete CPE name: {cpe_uri}"
        raise ValueError(message)

    return [_reference_unescape(part) for part in components]


def reference_split(cpe_uri: str) -> CpeIdentity:
    """Return the CPE type, vendor, product, version, and update fields.

    Args:
        cpe_uri: Formatted CPE name from NVD.

    Returns:
        A five-field tuple, filling omitted trailing fields with '*'.

    Raises:
        ValueError: If the CPE name is unsupported or incomplete.
    """
    components = _reference_split_components(cpe_uri)
    components.extend(["*"] * max(0, 5 - len(components)))
    return (
        components[0],
        components[1],
        components[2],
        components[3],
        components[4],
    )
