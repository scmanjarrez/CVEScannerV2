# SPDX-License-Identifier: GPL-3.0-or-later

"""Provide an interactive Textual interface for querying the CVE database.

Collect product filters and display matching CVE records in result tables.
"""

from pathlib import Path
from typing import ClassVar, Self

from rich.text import Text
from sqlalchemy.exc import SQLAlchemyError
from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal
from textual.suggester import Suggester
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    ProgressBar,
    Static,
    TabbedContent,
    TabPane,
)

from db_manager.application.query import (
    QueryArguments,
    QueryResultSet,
    fetch_results,
    suggest_product,
)
from db_manager.constants import EXACT_HEADERS, RANGE_HEADERS

FORM_FIELDS = ("product", "version", "update")


class ResultTable(DataTable[Text]):
    """Result table with Vim and Emacs style cursor navigation."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("j,ctrl+n", "cursor_down", "Down", show=False),
        Binding("k,ctrl+p", "cursor_up", "Up", show=False),
        Binding("h,ctrl+b", "cursor_left", "Left", show=False),
        Binding("l,ctrl+f", "cursor_right", "Right", show=False),
        Binding("g,alt+less_than_sign", "first_row", "First", show=False),
        Binding("G,alt+greater_than_sign", "last_row", "Last", show=False),
        Binding("ctrl+d,ctrl+v", "page_down", "Page down", show=False),
        Binding("ctrl+u,alt+v", "page_up", "Page up", show=False),
    ]

    def action_first_row(self: Self) -> None:
        """Move the cursor to the first row."""
        self.move_cursor(row=0)

    def action_last_row(self: Self) -> None:
        """Move the cursor to the last row."""
        self.move_cursor(row=self.row_count - 1)


class ProductSuggester(Suggester):
    """Look up product completions in SQLite on demand.

    Attributes:
        database_path: SQLite database used to find product names.
    """

    database_path: Path

    def __init__(self: Self, database_path: Path) -> None:
        """Initialize the suggester with its product database.

        Args:
            database_path: SQLite database path for product completion.
        """
        super().__init__(case_sensitive=False)
        self.database_path = database_path

    async def get_suggestion(self: Self, value: str) -> str | None:
        """Return a product completion for the current input prefix.

        Args:
            value: Current product input, case-folded by the suggester.

        Returns:
            The first matching product, or None when no match is found.
        """
        if not self.database_path.is_file():
            return None
        try:
            return await suggest_product(self.database_path, value)
        except SQLAlchemyError:
            return None


class DatabaseQueryApp(App[None]):
    """Search products and inspect their CVE matches in a terminal UI.

    Attributes:
        TITLE: Textual application title.
        CSS: Styles for the query form and result tables.
        database_path: SQLite database used for product lookup and queries.
        initial_product: Optional product prefilled from the command line.
    """

    TITLE: str | None = "CVEScannerV2 database query"
    CSS: ClassVar[str] = """
    #query-fields {
        height: auto;
        margin: 1 2 0 2;
    }
    #product {
        width: 1fr;
        min-width: 28;
    }
    #version, #update {
        width: 1fr;
        min-width: 18;
    }
    #actions {
        height: auto;
        margin: 1 2 0 2;
    }
    #clear {
        margin-left: 1;
    }
    #database-path, #status {
        height: auto;
        margin: 0 2;
    }
    #progress {
        height: 1;
        margin: 0 2;
        display: none;
    }
    #results {
        height: 1fr;
        margin: 1 1;
    }
    ResultTable {
        height: 1fr;
    }
    """

    ENABLE_COMMAND_PALETTE: ClassVar[bool] = False
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("ctrl+e", "show_exact", "Exact versions", priority=True),
        Binding("ctrl+r", "show_ranges", "Ranges", priority=True),
        Binding("ctrl+s", "search", "Search", priority=True),
        Binding("ctrl+l", "clear", "Clear", priority=True),
        Binding("ctrl+t", "focus_results", "Results", priority=True),
        Binding("ctrl+q", "quit", "Quit", priority=True),
        Binding("tab", "next_field", "Next field", show=False, priority=True),
        Binding(
            "shift+tab",
            "previous_field",
            "Previous field",
            show=False,
            priority=True,
        ),
    ]

    database_path: Path
    initial_product: str | None

    def __init__(
        self: Self,
        database_path: Path,
        initial_product: str | None = None,
    ) -> None:
        """Initialize the application with its database and optional query.

        Args:
            database_path: SQLite database path to use.
            initial_product: Optional initial product search value.
        """
        super().__init__()
        self.database_path = database_path
        self.initial_product = initial_product

    def compose(self: Self) -> ComposeResult:
        """Compose the query form, progress indicator, and result tabs.

        Returns:
            Widgets that make up the query interface.
        """
        yield Header()
        yield Static(
            Text(f"Database: {self.database_path}"), id="database-path"
        )
        with Horizontal(id="query-fields"):
            yield Input(
                value=self.initial_product or "",
                placeholder="Product name",
                id="product",
                suggester=ProductSuggester(self.database_path),
            )
            yield Input(placeholder="Version (optional)", id="version")
            yield Input(placeholder="Update (optional)", id="update")
        with Horizontal(id="actions"):
            yield Button("Search", variant="primary", id="search")
            yield Button("Clear", id="clear")
        yield Static("Enter a product name to search.", id="status")
        yield ProgressBar(total=None, show_eta=False, id="progress")
        with TabbedContent(id="results"):
            with TabPane("Exact versions", id="exact-pane"):
                yield ResultTable(id="exact-results", zebra_stripes=True)
            with TabPane("Version ranges", id="range-pane"):
                yield ResultTable(id="range-results", zebra_stripes=True)
        yield Footer()

    def on_mount(self: Self) -> None:
        """Prepare result tables and focus the product input.

        Disable search and display an error when the database is missing.
        """
        self.query_one("#exact-results", ResultTable).add_columns(
            *EXACT_HEADERS
        )
        self.query_one("#range-results", ResultTable).add_columns(
            *RANGE_HEADERS
        )
        if not self.database_path.is_file():
            self._set_status(
                f"Database not found: {self.database_path}. "
                "Pass its path with --cve."
            )
            self.query_one("#search", Button).disabled = True
            self.query_one("#product", Input).focus()
            return

        self._set_status(
            "Type a product name; press → to accept a database suggestion."
        )
        self.query_one("#product", Input).focus()

    async def on_button_pressed(
        self: Self,
        event: Button.Pressed,
    ) -> None:
        """Run or clear a query when an action button is pressed.

        Args:
            event: Textual button press event.
        """
        if event.button.id == "search":
            await self._search()
        elif event.button.id == "clear":
            self._clear()

    async def on_input_submitted(
        self: Self,
        event: Input.Submitted,
    ) -> None:
        """Run a query when Enter is pressed in one of the form fields.

        Args:
            event: Textual input submission event.
        """
        if event.input.id in {"product", "version", "update"}:
            await self._search()

    def action_show_exact(self: Self) -> None:
        """Switch to the exact-version results tab."""
        self.query_one("#results", TabbedContent).active = "exact-pane"

    def action_show_ranges(self: Self) -> None:
        """Switch to the version-range results tab."""
        self.query_one("#results", TabbedContent).active = "range-pane"

    def _cycle_field(self: Self, step: int) -> None:
        """Move focus through the form inputs, wrapping around.

        Args:
            step: Offset to apply: 1 for next, -1 for previous.
        """
        fields = [self.query_one(f"#{name}", Input) for name in FORM_FIELDS]
        current = self.focused
        if isinstance(current, Input) and current in fields:
            index = (fields.index(current) + step) % len(fields)
        else:
            index = 0 if step > 0 else len(fields) - 1
        fields[index].focus()

    def action_next_field(self: Self) -> None:
        """Focus the next form input."""
        self._cycle_field(1)

    def action_previous_field(self: Self) -> None:
        """Focus the previous form input."""
        self._cycle_field(-1)

    def action_focus_results(self: Self) -> None:
        """Focus the table of the active results tab."""
        active = self.query_one("#results", TabbedContent).active
        table_id = (
            "#exact-results" if active == "exact-pane" else "#range-results"
        )
        self.query_one(table_id, ResultTable).focus()

    async def action_search(self: Self) -> None:
        """Run the query from the keyboard."""
        await self._search()

    def action_clear(self: Self) -> None:
        """Clear the form and results from the keyboard."""
        self._clear()

    async def _search(self: Self) -> None:
        """Fetch matching records and update both result tables.

        Show progress during the query and restore controls afterward.
        """
        product = self.query_one("#product", Input).value.strip()
        if not product:
            self._set_status("Enter a product name to search.")
            self.query_one("#product", Input).focus()
            return

        version = self.query_one("#version", Input).value.strip() or None
        update = self.query_one("#update", Input).value.strip() or None
        arguments = QueryArguments(
            cve=self.database_path,
            product=product,
            version=version,
            update=update,
            raw=False,
            debug=False,
        )
        progress = self.query_one("#progress", ProgressBar)
        progress.display = True
        self.query_one("#product", Input).disabled = True
        self.query_one("#version", Input).disabled = True
        self.query_one("#update", Input).disabled = True
        self.query_one("#search", Button).disabled = True
        self.query_one("#clear", Button).disabled = True
        self._set_status(f"Searching for {product}…")
        self._clear_tables()
        try:
            results = await fetch_results(arguments)
        except (SQLAlchemyError, TypeError, ValueError) as error:
            self._set_status(f"Query failed: {error}")
        else:
            self._show_results(results)
        finally:
            progress.display = False
            self.query_one("#product", Input).disabled = False
            self.query_one("#version", Input).disabled = False
            self.query_one("#update", Input).disabled = False
            self.query_one("#search", Button).disabled = False
            self.query_one("#clear", Button).disabled = False

    def _show_results(
        self: Self,
        results: QueryResultSet,
    ) -> None:
        """Populate result tables and show the number of matches.

        Args:
            results: Filtered exact-version and version-range rows.
        """
        self.query_one("#exact-results", ResultTable).add_rows(
            [[Text(cell) for cell in row] for row in results.exact]
        )
        self.query_one("#range-results", ResultTable).add_rows(
            [[Text(cell) for cell in row] for row in results.ranges]
        )
        self._set_status(
            f"Found {len(results.exact)} exact-version and "
            f"{len(results.ranges)} version-range matches."
        )

    def _clear(self: Self) -> None:
        """Clear the form and both result tables.

        Reset the status and return focus to the product input.
        """
        self.query_one("#product", Input).value = ""
        self.query_one("#version", Input).value = ""
        self.query_one("#update", Input).value = ""
        self._clear_tables()
        self._set_status("Enter a product name to search.")
        self.query_one("#product", Input).focus()

    def _clear_tables(self: Self) -> None:
        """Remove rows while keeping the result table columns.

        Clear both tables without changing their configured headers.
        """
        self.query_one("#exact-results", ResultTable).clear()
        self.query_one("#range-results", ResultTable).clear()

    def _set_status(self: Self, message: str) -> None:
        """Display plain status text without interpreting Rich markup.

        Args:
            message: Status message to show below the query form.
        """
        self.query_one("#status", Static).update(Text(message))
