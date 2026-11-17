# SPDX-License-Identifier: GPL-3.0-or-later

"""Check that the CPE parser matches the frozen reference implementation.

Each case compares the production split function with reference_split. When
the reference raises, the production function must raise the same exception
class with the same message.
"""

import unittest

from db_manager.domain.cpe import split
from tests.reference_cpe import reference_split

VALID_CPES: tuple[str, ...] = (
    "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
    "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
    "cpe:/a:vendor:product:1.0",
    "cpe:/a:vendor:product",
    "cpe:/a:v:p:1:upd",
    r"cpe:2.3:a:ven\:dor:prod\\uct:1\.0:*:*:*:*:*:*:*",
    r"cpe:2.3:a:v:p:1\\:2:*:*:*:*:*:*:*",
    "cpe:2.3:a:v:p:1\\",
    "cpe:2.3:a::p:1:*",
)

INVALID_CPES: tuple[str, ...] = (
    "cpe:2.3:a:v",
    "cpe:2.3:a",
    "foo:bar",
    "",
    "cpe:/",
)


class CpeEquivalenceTest(unittest.TestCase):
    """Compare the production CPE parser with the frozen reference."""

    def _assert_equivalent(self, cpe_uri: str) -> None:
        """Assert that split matches reference_split for one CPE name.

        Args:
            cpe_uri: CPE name to parse with both implementations.
        """
        try:
            expected = reference_split(cpe_uri)
        except ValueError as reference_error:
            with self.assertRaises(ValueError) as context:
                split(cpe_uri)
            self.assertEqual(str(context.exception), str(reference_error))
        else:
            self.assertEqual(split(cpe_uri), expected)

    def test_valid_and_escaped_cpes_match_reference(self) -> None:
        """Return the same identity as the reference for valid CPE names."""
        for cpe_uri in VALID_CPES:
            with self.subTest(cpe=cpe_uri):
                self._assert_equivalent(cpe_uri)

    def test_invalid_cpes_match_reference_errors(self) -> None:
        """Raise the same ValueError as the reference for invalid names."""
        for cpe_uri in INVALID_CPES:
            with self.subTest(cpe=cpe_uri):
                self._assert_equivalent(cpe_uri)

    def test_repeated_invalid_cpe_raises_same_error(self) -> None:
        """Raise an identical ValueError on each call with an invalid CPE."""
        cpe_uri = "cpe:2.3:a:v"
        messages: list[str] = []
        for _ in range(2):
            with self.assertRaises(ValueError) as context:
                split(cpe_uri)
            messages.append(str(context.exception))
        self.assertEqual(messages[0], messages[1])

    def test_repeated_valid_cpe_returns_equal_values(self) -> None:
        """Return equal identities on each call with a valid CPE."""
        cpe_uri = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
        self.assertEqual(split(cpe_uri), split(cpe_uri))


if __name__ == "__main__":
    unittest.main()
