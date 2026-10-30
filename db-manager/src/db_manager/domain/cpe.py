# SPDX-License-Identifier: GPL-3.0-or-later

"""Parse CPE names and NVD configuration match trees.

Convert vulnerable CPE criteria into product identities and version bounds.
"""

import functools
import re

from db_manager.constants import MIN_CPE_COMPONENTS

from .models import (
    CpeIdentity,
    NvdConfiguration,
    NvdConfigurationNode,
    VersionBounds,
)

ParsedNodeMatch = tuple[CpeIdentity, VersionBounds]
ParsedCondition = tuple[CpeIdentity, CpeIdentity]

_ESCAPE = re.compile(r"\\(.)")
_SPLIT_CACHE_SIZE: int = 524_288


def _unescape_cpe_component(value: str) -> str:
    """Remove CPE escape markers from one parsed component.

    Args:
        value: CPE component with formatted-string escape markers.

    Returns:
        The component with escaped characters decoded.
    """
    return _ESCAPE.sub(r"\1", value)


def _split_escaped_fields(value: str) -> list[str]:
    """Split CPE fields while keeping escaped colons inside their field.

    Args:
        value: CPE fields after the scheme and version prefix, containing
            at least one backslash.

    Returns:
        Raw CPE fields with escape markers still present.
    """
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
    return components


def _split_cpe_components(cpe_uri: str) -> list[str]:
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

    has_escapes = "\\" in value
    if has_escapes:
        components = _split_escaped_fields(value)
    else:
        components = value.split(":")

    if value.startswith("/") and components:
        components[0] = components[0][1:]
    if len(components) < MIN_CPE_COMPONENTS:
        message = f"Incomplete CPE name: {cpe_uri}"
        raise ValueError(message)

    if not has_escapes:
        return components
    # A backslash escapes the following character in a CPE component. Keep
    # escaped colons inside their field, then remove the escape marker.
    return [_unescape_cpe_component(part) for part in components]


def _split_uncached(cpe_uri: str) -> CpeIdentity:
    """Build the identity for a formatted CPE name without memoization.

    Args:
        cpe_uri: Formatted CPE name from NVD.

    Returns:
        A five-field tuple, filling omitted trailing fields with '*'.

    Raises:
        ValueError: If the CPE name is unsupported or incomplete.
    """
    components = _split_cpe_components(cpe_uri)
    components.extend(["*"] * max(0, 5 - len(components)))
    return (
        components[0],
        components[1],
        components[2],
        components[3],
        components[4],
    )


def split(cpe_uri: str) -> CpeIdentity:
    """Return the CPE type, vendor, product, version, and update fields.

    Args:
        cpe_uri: Formatted CPE name from NVD.

    Returns:
        A five-field tuple, filling omitted trailing fields with '*'.

    Raises:
        ValueError: If the CPE name is unsupported or incomplete.
    """
    return _split_uncached(cpe_uri)


@functools.lru_cache(maxsize=_SPLIT_CACHE_SIZE)
def _split_cached(cpe_uri: str) -> CpeIdentity:
    """Return the memoized CPE identity for a criteria string.

    Args:
        cpe_uri: Formatted CPE criteria name from an NVD configuration.

    Returns:
        A five-field tuple, filling omitted trailing fields with '*'.

    Raises:
        ValueError: If the CPE name is unsupported or incomplete.
    """
    return split(cpe_uri)


def _version_bound(value: str | None) -> str | None:
    """Unescape a version bound when NVD supplied one.

    Args:
        value: NVD version boundary or None.

    Returns:
        The decoded version boundary, or None when it is absent.
    """
    if value is None:
        return None
    return _unescape_cpe_component(value)


def parse_node(node: NvdConfigurationNode) -> list[ParsedNodeMatch]:
    """Return vulnerable CPE matches from a node and its children.

    Args:
        node: Recursive NVD configuration node.

    Returns:
        A list of vulnerable CPE identities with their version bounds.

    Raises:
        ValueError: If a CPE criteria string is unsupported or incomplete.
    """
    # A negated node describes the absence of its CPE criteria, so none of
    # its entries can independently establish that a product is affected.
    if node.negate:
        return []

    matches: list[ParsedNodeMatch] = []
    for cpe in node.cpe_match:
        # NVD also lists platform and environment CPEs in a configuration.
        # Only vulnerable=true entries identify products affected by the CVE.
        if cpe.vulnerable is not True:
            continue
        bounds: VersionBounds = (
            _version_bound(cpe.version_start_including),
            _version_bound(cpe.version_start_excluding),
            _version_bound(cpe.version_end_including),
            _version_bound(cpe.version_end_excluding),
        )
        matches.append((_split_cached(cpe.criteria), bounds))

    for child in node.children:
        matches.extend(parse_node(child))
    return matches


def _has_and_operator(node: NvdConfigurationNode) -> bool:
    """Return whether a node or any nested child uses AND.

    Args:
        node: Recursive NVD configuration node.

    Returns:
        True when this node or one of its descendants declares AND.
    """
    if node.operator == "AND":
        return True
    return any(_has_and_operator(child) for child in node.children)


def _platform_identities(node: NvdConfigurationNode) -> list[CpeIdentity]:
    """Return non-negated platform CPE identities from a node tree.

    Args:
        node: Recursive NVD configuration node.

    Returns:
        Identities of CPE entries marked vulnerable=false.

    Raises:
        ValueError: If a CPE criteria string is unsupported or incomplete.
    """
    if node.negate:
        return []
    identities: list[CpeIdentity] = [
        _split_cached(cpe.criteria)
        for cpe in node.cpe_match
        if cpe.vulnerable is False
    ]
    for child in node.children:
        identities.extend(_platform_identities(child))
    return identities


def parse_conditions(config: NvdConfiguration) -> list[ParsedCondition]:
    """Pair vulnerable products with platforms in AND configurations.

    An OR-only configuration yields no pairs because each vulnerable entry
    already stands alone. A configuration that declares AND at its root or
    in any node requires its platforms to be paired with each product.

    Args:
        config: NVD configuration to inspect.

    Returns:
        Pairs of (vulnerable product identity, platform identity). Empty
        when the configuration does not use AND.

    Raises:
        ValueError: If a CPE criteria string is unsupported or incomplete.
    """
    is_and = config.operator == "AND" or any(
        _has_and_operator(node) for node in config.nodes
    )
    if not is_and:
        return []
    vulnerable = [
        identity
        for node in config.nodes
        for identity, _bounds in parse_node(node)
    ]
    platforms = [
        identity
        for node in config.nodes
        for identity in _platform_identities(node)
    ]
    return [
        (product, platform) for product in vulnerable for platform in platforms
    ]
