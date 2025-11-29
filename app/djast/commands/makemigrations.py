import ast
import shutil
import subprocess
from pathlib import Path
from alembic.config import Config
from alembic import command

from djast.settings import ROOT_DIR

TEMPLATES_DIR = ROOT_DIR / "djast" / "templates"


def detect_and_handle_renames(file_path):
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

    def get_name(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Str):
            return node.s
        return None

    def extract_operations(func_node):
        created_tables = {}
        dropped_tables = {}
        added_columns = []
        dropped_columns = []

        if not func_node:
            return created_tables, dropped_tables, added_columns, dropped_columns

        for stmt in func_node.body:
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                if (
                    isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == "op"
                ):
                    if call.func.attr == "create_table":
                        name = get_name(call.args[0])
                        if name:
                            created_tables[name] = stmt
                    elif call.func.attr == "drop_table":
                        name = get_name(call.args[0])
                        if name:
                            dropped_tables[name] = stmt
                    elif call.func.attr == "add_column":
                        t_name = get_name(call.args[0])
                        c_name = None
                        if len(call.args) > 1:
                            col_def = call.args[1]
                            if isinstance(col_def, ast.Call):
                                if (
                                    isinstance(col_def.func, ast.Name)
                                    and col_def.func.id == "Column"
                                ) or (
                                    isinstance(col_def.func, ast.Attribute)
                                    and col_def.func.attr == "Column"
                                ):
                                    if col_def.args:
                                        c_name = get_name(col_def.args[0])
                        if t_name and c_name:
                            added_columns.append(
                                {
                                    "table": t_name,
                                    "col": c_name,
                                    "node": stmt,
                                    "is_batch": False,
                                }
                            )
                    elif call.func.attr == "drop_column":
                        t_name = get_name(call.args[0])
                        c_name = (
                            get_name(call.args[1])
                            if len(call.args) > 1
                            else None
                        )
                        if t_name and c_name:
                            dropped_columns.append(
                                {
                                    "table": t_name,
                                    "col": c_name,
                                    "node": stmt,
                                    "is_batch": False,
                                }
                            )

            elif isinstance(stmt, ast.With):
                is_batch = False
                table_name = None
                batch_var = None

                for item in stmt.items:
                    if isinstance(item.context_expr, ast.Call):
                        c = item.context_expr
                        if (
                            isinstance(c.func, ast.Attribute)
                            and c.func.attr == "batch_alter_table"
                        ):
                            if c.args:
                                table_name = get_name(c.args[0])
                            if item.optional_vars and isinstance(
                                item.optional_vars, ast.Name
                            ):
                                batch_var = item.optional_vars.id
                                is_batch = True

                if is_batch and table_name and batch_var:
                    for sub_stmt in stmt.body:
                        if isinstance(sub_stmt, ast.Expr) and isinstance(
                            sub_stmt.value, ast.Call
                        ):
                            sub_call = sub_stmt.value
                            if (
                                isinstance(sub_call.func, ast.Attribute)
                                and isinstance(sub_call.func.value, ast.Name)
                                and sub_call.func.value.id == batch_var
                            ):
                                if sub_call.func.attr == "add_column":
                                    c_name = None
                                    if sub_call.args:
                                        col_def = sub_call.args[0]
                                        if isinstance(col_def, ast.Call):
                                            if (
                                                isinstance(
                                                    col_def.func, ast.Name
                                                )
                                                and col_def.func.id == "Column"
                                            ) or (
                                                isinstance(
                                                    col_def.func, ast.Attribute
                                                )
                                                and col_def.func.attr
                                                == "Column"
                                            ):
                                                if col_def.args:
                                                    c_name = get_name(
                                                        col_def.args[0]
                                                    )
                                    if c_name:
                                        added_columns.append(
                                            {
                                                "table": table_name,
                                                "col": c_name,
                                                "node": sub_stmt,
                                                "is_batch": True,
                                                "batch_var": batch_var,
                                            }
                                        )
                                elif sub_call.func.attr == "drop_column":
                                    c_name = (
                                        get_name(sub_call.args[0])
                                        if sub_call.args
                                        else None
                                    )
                                    if c_name:
                                        dropped_columns.append(
                                            {
                                                "table": table_name,
                                                "col": c_name,
                                                "node": sub_stmt,
                                                "is_batch": True,
                                                "batch_var": batch_var,
                                            }
                                        )
        return created_tables, dropped_tables, added_columns, dropped_columns

    (
        up_created_tables,
        up_dropped_tables,
        up_added_columns,
        up_dropped_columns,
    ) = extract_operations(upgrade_node)
    (
        down_created_tables,
        down_dropped_tables,
        down_added_columns,
        down_dropped_columns,
    ) = extract_operations(downgrade_node)

    replacements = []

    # Check table renames
    for drop_name, drop_node in list(up_dropped_tables.items()):
        for create_name, create_node in list(up_created_tables.items()):
            if (
                drop_name in up_dropped_tables
                and create_name in up_created_tables
            ):
                answer = input(
                    f"Did you rename table from '{drop_name}' to '{create_name}'? [y/N]: "
                )
                if answer.lower() == "y":
                    # Upgrade changes
                    replacements.append((drop_node, ""))

                    indent = " " * create_node.col_offset
                    new_code = f"op.rename_table('{drop_name}', '{create_name}')\n"

                    replacements.append((create_node, new_code))

                    # Downgrade changes
                    # In downgrade, we expect create_table(drop_name) and drop_table(create_name)
                    down_create_node = down_created_tables.get(drop_name)
                    down_drop_node = down_dropped_tables.get(create_name)

                    if down_create_node and down_drop_node:
                        indent_down = " " * down_create_node.col_offset
                        new_code_down = f"op.rename_table('{create_name}', '{drop_name}')\n"

                        replacements.append((down_create_node, new_code_down))
                        replacements.append((down_drop_node, ""))

                    del up_dropped_tables[drop_name]
                    del up_created_tables[create_name]
                    break

    # Check column renames
    for drop in list(up_dropped_columns):
        for add in list(up_added_columns):
            if drop["table"] == add["table"]:
                answer = input(
                    f"Did you rename column '{drop['col']}' to '{add['col']}' in table '{drop['table']}'? [y/N]: "
                )
                if answer.lower() == "y":
                    # Upgrade changes
                    replacements.append((drop["node"], ""))

                    if add["is_batch"]:
                        new_code = f"{add['batch_var']}.alter_column('{drop['col']}', new_column_name='{add['col']}')"
                    else:
                        new_code = f"op.alter_column('{drop['table']}', '{drop['col']}', new_column_name='{add['col']}')"

                    replacements.append((add["node"], new_code))

                    # Downgrade changes
                    # In downgrade, we expect add_column(drop['col']) and drop_column(add['col'])
                    down_add_node = None
                    down_drop_node = None

                    for da in down_added_columns:
                        if (
                            da["table"] == drop["table"]
                            and da["col"] == drop["col"]
                        ):
                            down_add_node = da
                            break

                    for dd in down_dropped_columns:
                        if (
                            dd["table"] == drop["table"]
                            and dd["col"] == add["col"]
                        ):
                            down_drop_node = dd
                            break

                    if down_add_node and down_drop_node:
                        replacements.append((down_add_node["node"], ""))

                        if down_drop_node["is_batch"]:
                            new_code_down = f"{down_drop_node['batch_var']}.alter_column('{add['col']}', new_column_name='{drop['col']}')"
                        else:
                            new_code_down = f"op.alter_column('{drop['table']}', '{add['col']}', new_column_name='{drop['col']}')"

                        replacements.append(
                            (down_drop_node["node"], new_code_down)
                        )

                    up_dropped_columns.remove(drop)
                    up_added_columns.remove(add)
                    break

    if replacements:
        lines = content.splitlines(keepends=True)

        def get_range(node):
            start_line = node.lineno - 1
            start_col = node.col_offset
            end_line = node.end_lineno - 1
            end_col = node.end_col_offset

            start_idx = 0
            for i in range(start_line):
                start_idx += len(lines[i])
            start_idx += start_col

            end_idx = 0
            for i in range(end_line):
                end_idx += len(lines[i])
            end_idx += end_col

            return start_idx, end_idx

        repl_ranges = []
        for node, text in replacements:
            s, e = get_range(node)
            repl_ranges.append((s, e, text))

        repl_ranges.sort(key=lambda x: x[0], reverse=True)

        new_content = content
        for s, e, text in repl_ranges:
            new_content = new_content[:s] + text + new_content[e:]

        with open(file_path, "w") as f:
            f.write(new_content)

        print("Applied rename changes to migration.")


def run(message: str = "auto"):
    """ Creates a new Alembic migration with the given message. If Alembic is
    not initialized, then it initializes it first.

    Args:
        message (str): The message for the new migration. Defaults to "auto".
    """
    alembic_ini = ROOT_DIR / "alembic.ini"
    migrations_dir = ROOT_DIR / "migrations"

    if not alembic_ini.exists():
        print("Initializing Alembic...")
        # Run alembic init -t async migrations
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

        ini_content = ini_content.replace(
            "# file_template = %%(year)d_%%(month).2d_%%(day).2d_"
            "%%(hour).2d%%(minute).2d-%%(rev)s_%%(slug)s",
            "file_template = %%(year)d_%%(month).2d_%%(day).2d_"
            "%%(hour).2d%%(minute).2d-%%(rev)s_%%(slug)s",
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
                    if hasattr(ast, "get_source_segment"):
                        upgrade_code = ast.get_source_segment(content, node)
                    else:
                        # Fallback for older python versions if needed,
                        # though get_source_segment is 3.8+
                        upgrade_code = content
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
