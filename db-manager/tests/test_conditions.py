# SPDX-License-Identifier: GPL-3.0-or-later

"""Check AND-condition extraction from NVD configurations.

Each case builds a configuration from NVD-shaped data and verifies which
vulnerable product and platform pairs parse_conditions returns.
"""

import unittest

from db_manager.domain.cpe import parse_conditions, parse_node
from db_manager.domain.models import NvdConfiguration

PHP_CPE = "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"
WINDOWS_CPE = "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"


def _match(criteria: str, *, vulnerable: bool) -> dict[str, object]:
    """Build one NVD cpeMatch entry.

    Args:
        criteria: Formatted CPE name.
        vulnerable: Whether the entry identifies an affected product.

    Returns:
        A dictionary shaped like an NVD cpeMatch entry.
    """
    return {"criteria": criteria, "vulnerable": vulnerable}


class ParseConditionsTests(unittest.TestCase):
    """Verify the AND pairing rules for NVD configurations."""

    def test_and_pairs_vulnerable_with_platform(self) -> None:
        """Pair a vulnerable product with a platform under AND."""
        config = NvdConfiguration.model_validate(
            {
                "operator": "AND",
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [_match(PHP_CPE, vulnerable=True)],
                    },
                    {
                        "operator": "OR",
                        "cpeMatch": [_match(WINDOWS_CPE, vulnerable=False)],
                    },
                ],
            }
        )

        pairs = parse_conditions(config)

        self.assertEqual(
            pairs,
            [
                (
                    ("a", "php", "php", "*", "*"),
                    ("o", "microsoft", "windows", "*", "*"),
                )
            ],
        )

    def test_or_only_configuration_yields_no_pairs(self) -> None:
        """Return an empty list when no node or config uses AND."""
        config = NvdConfiguration.model_validate(
            {
                "operator": "OR",
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            _match(PHP_CPE, vulnerable=True),
                            _match(WINDOWS_CPE, vulnerable=False),
                        ],
                    }
                ],
            }
        )

        self.assertEqual(parse_conditions(config), [])

    def test_nested_and_node_is_detected(self) -> None:
        """Detect AND declared on a nested child node."""
        config = NvdConfiguration.model_validate(
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "children": [
                            {
                                "operator": "AND",
                                "cpeMatch": [
                                    _match(PHP_CPE, vulnerable=True),
                                    _match(WINDOWS_CPE, vulnerable=False),
                                ],
                            }
                        ],
                    }
                ],
            }
        )

        pairs = parse_conditions(config)

        self.assertEqual(
            pairs,
            [
                (
                    ("a", "php", "php", "*", "*"),
                    ("o", "microsoft", "windows", "*", "*"),
                )
            ],
        )

    def test_missing_operator_yields_no_pairs(self) -> None:
        """Treat a configuration without operator as OR."""
        config = NvdConfiguration.model_validate(
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            _match(PHP_CPE, vulnerable=True),
                            _match(WINDOWS_CPE, vulnerable=False),
                        ],
                    }
                ],
            }
        )

        self.assertEqual(parse_conditions(config), [])

    def test_negated_platform_is_ignored(self) -> None:
        """Skip platform CPEs that sit under a negated node."""
        config = NvdConfiguration.model_validate(
            {
                "operator": "AND",
                "nodes": [
                    {
                        "cpeMatch": [_match(PHP_CPE, vulnerable=True)],
                    },
                    {
                        "negate": True,
                        "cpeMatch": [_match(WINDOWS_CPE, vulnerable=False)],
                    },
                ],
            }
        )

        self.assertEqual(parse_conditions(config), [])

    def test_parse_node_returns_only_vulnerable_entries(self) -> None:
        """Keep parse_node limited to vulnerable=true CPE entries."""
        config = NvdConfiguration.model_validate(
            {
                "operator": "AND",
                "nodes": [
                    {
                        "cpeMatch": [
                            _match(PHP_CPE, vulnerable=True),
                            _match(WINDOWS_CPE, vulnerable=False),
                        ],
                    }
                ],
            }
        )

        matches = parse_node(config.nodes[0])

        self.assertEqual(
            [identity for identity, _bounds in matches],
            [("a", "php", "php", "*", "*")],
        )


if __name__ == "__main__":
    unittest.main()
