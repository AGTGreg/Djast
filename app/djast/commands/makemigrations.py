"""Generate a new Alembic migration."""

import ast
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from alembic.config import Config
from alembic import command

from djast.settings import ROOT_DIR

TEMPLATES_DIR = ROOT_DIR / "djast" / "templates"

Replacement = tuple[ast.stmt, str]


@dataclass
class MigrationOperations:
    """Parsed Alembic migration operations from upgrade/downgrade functions."""

    created_tables: dict[str, ast.stmt] = field(default_factory=dict)
    dropped_tables: dict[str, ast.stmt] = field(default_factory=dict)
    added_columns: list[dict[str, Any]] = field(default_factory=list)
    dropped_columns: list[dict[str, Any]] = field(default_factory=list)


def _get_name(node: ast.expr) -> str | None:
    """Extract a string constant value from an AST node."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_op_call(call: ast.Call) -> bool:
    """Check if a Call node is an `op.<method>(...)` call."""
    return (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "op"
    )


def _extract_column_name(col_def: ast.expr) -> str | None:
    """Extract the column name from a `Column(name, ...)` or `sa.Column(name, ...)` call."""
    if not isinstance(col_def, ast.Call):
        return None
    if (
        isinstance(col_def.func, ast.Name) and col_def.func.id == "Column"
    ) or (
        isinstance(col_def.func, ast.Attribute)
        and col_def.func.attr == "Column"
    ):
        if col_def.args:
            return _get_name(col_def.args[0])
    return None


def _extract_top_level_ops(
    stmt: ast.stmt, ops: MigrationOperations
) -> None:
    """Extract operations from a top-level `op.<method>(...)` statement."""
    if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)):
        return
    call = stmt.value
    if not _is_op_call(call):
        return

    attr = call.func.attr
    if attr == "create_table":
        name = _get_name(call.args[0])
        if name:
            ops.created_tables[name] = stmt
    elif attr == "drop_table":
        name = _get_name(call.args[0])
        if name:
            ops.dropped_tables[name] = stmt
    elif attr == "add_column":
        t_name = _get_name(call.args[0])
        c_name = _extract_column_name(call.args[1]) if len(call.args) > 1 else None
        if t_name and c_name:
            ops.added_columns.append(
                {"table": t_name, "col": c_name, "node": stmt, "is_batch": False}
            )
    elif attr == "drop_column":
        t_name = _get_name(call.args[0])
        c_name = _get_name(call.args[1]) if len(call.args) > 1 else None
        if t_name and c_name:
            ops.dropped_columns.append(
                {"table": t_name, "col": c_name, "node": stmt, "is_batch": False}
            )


def _extract_batch_ops(
    stmt: ast.With, ops: MigrationOperations
) -> None:
    """Extract operations from a `with op.batch_alter_table(...) as batch_op:` block."""
    table_name = None
    batch_var = None

    for item in stmt.items:
        if not isinstance(item.context_expr, ast.Call):
            continue
        c = item.context_expr
        if isinstance(c.func, ast.Attribute) and c.func.attr == "batch_alter_table":
            if c.args:
                table_name = _get_name(c.args[0])
            if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                batch_var = item.optional_vars.id

    if not (table_name and batch_var):
        return

    for sub_stmt in stmt.body:
        if not (isinstance(sub_stmt, ast.Expr) and isinstance(sub_stmt.value, ast.Call)):
            continue
        sub_call = sub_stmt.value
        if not (
            isinstance(sub_call.func, ast.Attribute)
            and isinstance(sub_call.func.value, ast.Name)
            and sub_call.func.value.id == batch_var
        ):
            continue

        if sub_call.func.attr == "add_column":
            c_name = _extract_column_name(sub_call.args[0]) if sub_call.args else None
            if c_name:
                ops.added_columns.append(
                    {
                        "table": table_name, "col": c_name, "node": sub_stmt,
                        "is_batch": True, "batch_var": batch_var,
                    }
                )
        elif sub_call.func.attr == "drop_column":
            c_name = _get_name(sub_call.args[0]) if sub_call.args else None
            if c_name:
                ops.dropped_columns.append(
                    {
                        "table": table_name, "col": c_name, "node": sub_stmt,
                        "is_batch": True, "batch_var": batch_var,
                    }
                )


def extract_operations(func_node: ast.FunctionDef | None) -> MigrationOperations:
    """Parse an upgrade/downgrade function and extract all Alembic operations."""
    ops = MigrationOperations()
    if not func_node:
        return ops

    for stmt in func_node.body:
        if isinstance(stmt, ast.With):
            _extract_batch_ops(stmt, ops)
        else:
            _extract_top_level_ops(stmt, ops)

    return ops


def detect_table_renames(
    up_ops: MigrationOperations, down_ops: MigrationOperations
) -> list[Replacement]:
    """Prompt user for table renames and return AST node replacements."""
    replacements: list[Replacement] = []

    for drop_name, drop_node in list(up_ops.dropped_tables.items()):
        for create_name, create_node in list(up_ops.created_tables.items()):
            answer = input(
                f"Did you rename table from '{drop_name}' to '{create_name}'? [y/N]: "
            )
            if answer.lower() != "y":
                continue

            # Upgrade: replace drop + create with rename
            indent = " " * create_node.col_offset
            replacements.append((drop_node, ""))
            replacements.append(
                (create_node, f"{indent}op.rename_table('{drop_name}', '{create_name}')\n")
            )

            # Downgrade: reverse the rename
            down_create = down_ops.created_tables.get(drop_name)
            down_drop = down_ops.dropped_tables.get(create_name)
            if down_create and down_drop:
                indent_down = " " * down_create.col_offset
                replacements.append(
                    (down_create, f"{indent_down}op.rename_table('{create_name}', '{drop_name}')\n")
                )
                replacements.append((down_drop, ""))

            del up_ops.dropped_tables[drop_name]
            del up_ops.created_tables[create_name]
            break

    return replacements


def detect_column_renames(
    up_ops: MigrationOperations, down_ops: MigrationOperations
) -> list[Replacement]:
    """Prompt user for column renames and return AST node replacements.

    Only prompts when a table has exactly 1 dropped and 1 added column to
    avoid excessive false-positive prompts.
    """
    replacements: list[Replacement] = []

    # Group by table to apply heuristic
    drops_by_table: dict[str, list[dict[str, Any]]] = defaultdict(list)
    adds_by_table: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for drop in up_ops.dropped_columns:
        drops_by_table[drop["table"]].append(drop)
    for add in up_ops.added_columns:
        adds_by_table[add["table"]].append(add)

    for table, table_drops in drops_by_table.items():
        table_adds = adds_by_table.get(table, [])
        if len(table_drops) != 1 or len(table_adds) != 1:
            if table_drops and table_adds:
                print(
                    f"Note: Table '{table}' has multiple column changes. "
                    "Edit the migration manually if any are renames."
                )
            continue

        drop = table_drops[0]
        add = table_adds[0]

        answer = input(
            f"Did you rename column '{drop['col']}' to '{add['col']}' "
            f"in table '{drop['table']}'? [y/N]: "
        )
        if answer.lower() != "y":
            continue

        # Upgrade: replace drop + add with alter_column rename
        replacements.append((drop["node"], ""))
        if add["is_batch"]:
            new_code = (
                f"{add['batch_var']}.alter_column("
                f"'{drop['col']}', new_column_name='{add['col']}')"
            )
        else:
            new_code = (
                f"op.alter_column('{drop['table']}', "
                f"'{drop['col']}', new_column_name='{add['col']}')"
            )
        replacements.append((add["node"], new_code))

        # Downgrade: reverse the rename
        down_add = next(
            (da for da in down_ops.added_columns
             if da["table"] == drop["table"] and da["col"] == drop["col"]),
            None,
        )
        down_drop = next(
            (dd for dd in down_ops.dropped_columns
             if dd["table"] == drop["table"] and dd["col"] == add["col"]),
            None,
        )

        if down_add and down_drop:
            replacements.append((down_add["node"], ""))
            if down_drop["is_batch"]:
                new_code_down = (
                    f"{down_drop['batch_var']}.alter_column("
                    f"'{add['col']}', new_column_name='{drop['col']}')"
                )
            else:
                new_code_down = (
                    f"op.alter_column('{drop['table']}', "
                    f"'{add['col']}', new_column_name='{drop['col']}')"
                )
            replacements.append((down_drop["node"], new_code_down))

        up_ops.dropped_columns.remove(drop)
        up_ops.added_columns.remove(add)

    return replacements


def _get_node_range(
    node: ast.stmt, lines: list[str]
) -> tuple[int, int]:
    """Convert an AST node's line/col position to a character offset range."""
    start_line = node.lineno - 1
    start_col = node.col_offset
    end_line = node.end_lineno - 1
    end_col = node.end_col_offset

    start_idx = sum(len(lines[i]) for i in range(start_line)) + start_col
    end_idx = sum(len(lines[i]) for i in range(end_line)) + end_col

    return start_idx, end_idx


def apply_replacements(
    file_path: Path, content: str, replacements: list[Replacement]
) -> None:
    """Apply AST node replacements to a migration file."""
    if not replacements:
        return

    lines = content.splitlines(keepends=True)
    repl_ranges = []
    for node, text in replacements:
        s, e = _get_node_range(node, lines)
        repl_ranges.append((s, e, text))

    # Apply in reverse order to preserve earlier offsets
    repl_ranges.sort(key=lambda x: x[0], reverse=True)

    new_content = content
    for s, e, text in repl_ranges:
        new_content = new_content[:s] + text + new_content[e:]

    with open(file_path, "w") as f:
        f.write(new_content)

    print("Applied rename changes to migration.")


def detect_and_handle_renames(file_path: Path) -> None:
    """Detect table/column renames in a migration and rewrite as rename operations."""
    with open(file_path, "r") as f:
        content = f.read()

    try:
        tree = ast.parse(content)
    except Exception:
        return

    upgrade_node = None
    downgrade_node = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if node.name == "upgrade":
                upgrade_node = node
            elif node.name == "downgrade":
                downgrade_node = node

    if not upgrade_node:
        return

    up_ops = extract_operations(upgrade_node)
    down_ops = extract_operations(downgrade_node)

    replacements: list[Replacement] = []
    replacements.extend(detect_table_renames(up_ops, down_ops))
    replacements.extend(detect_column_renames(up_ops, down_ops))

    apply_replacements(file_path, content, replacements)


def run(message: str = "auto") -> None:
    """Create a new Alembic migration. Initializes Alembic on first run."""
    alembic_ini = ROOT_DIR / "alembic.ini"
    migrations_dir = ROOT_DIR / "migrations"

    if not alembic_ini.exists():
        print("Initializing Alembic...")
        subprocess.run(
            ["alembic", "init", "-t", "async", "migrations"],
            cwd=ROOT_DIR,
            check=True,
        )

        # Overwrite env.py with our template
        shutil.copy(TEMPLATES_DIR / "alembic_env.py", migrations_dir / "env.py")

        # Update alembic.ini to use a chronological file template
        with open(alembic_ini, "r") as f:
            ini_content = f.read()

        original_ini = ini_content
        ini_content = ini_content.replace(
            "# file_template = %%(year)d_%%(month).2d_%%(day).2d_"
            "%%(hour).2d%%(minute).2d-%%(rev)s_%%(slug)s",
            "file_template = %%(year)d_%%(month).2d_%%(day).2d_"
            "%%(hour).2d%%(minute).2d-%%(rev)s_%%(slug)s",
        )

        if ini_content == original_ini:
            print(
                "Warning: Could not set file_template in alembic.ini. "
                "You may need to configure it manually."
            )

        with open(alembic_ini, "w") as f:
            f.write(ini_content)

        print("Alembic initialized.")

    print(f"Generating migration with message: {message}")

    alembic_cfg = Config(str(alembic_ini))
    alembic_cfg.set_main_option("script_location", str(migrations_dir))

    command.revision(alembic_cfg, message=message, autogenerate=True)

    versions_dir = migrations_dir / "versions"
    files = list(versions_dir.glob("*.py"))

    if files:
        latest_file = max(files, key=lambda f: f.stat().st_mtime)

        detect_and_handle_renames(latest_file)

        with open(latest_file, "r") as f:
            content = f.read()

        upgrade_code = ""
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.FunctionDef)
                    and node.name == "upgrade"
                ):
                    upgrade_code = ast.get_source_segment(content, node)
                    break
        except Exception:
            upgrade_code = content

        warnings = []
        if upgrade_code and "op.drop_table" in upgrade_code:
            warnings.append("Dropping a table (op.drop_table)")
        if upgrade_code and "op.drop_column" in upgrade_code:
            warnings.append("Dropping a column (op.drop_column)")

        if warnings:
            print(
                f"\nWARNING: The generated migration '{latest_file.name}' "
                "contains potentially dangerous operations:"
            )
            for w in warnings:
                print(f"  - {w}")
            print("These operations can lead to DATA LOSS.")

            proceed = input("Do you want to keep this migration? [y/N]: ")
            if proceed.lower() != 'y':
                print(f"Deleting {latest_file.name}...")
                latest_file.unlink()
                print("Migration deleted.")
            else:
                print("Migration kept.")
