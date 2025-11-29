import shutil
from pathlib import Path
from djast.settings import ROOT_DIR


def run(module_name: str):
    if not module_name:
        print("Error: Module name is required.")
        return

    app_dir = ROOT_DIR
    template_dir = app_dir / "djast" / "templates" / "module"
    while (app_dir / module_name).exists():
        print(f"Error: Module '{module_name}' already exists.")
        try:
            module_name = input(
                "Please enter a different module name: "
            ).strip()
            if not module_name:
                print("Error: Module name is required.")
                return
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return

    new_module_dir = app_dir / module_name

    print(f"Creating module '{module_name}'...")

    try:
        shutil.copytree(template_dir, new_module_dir)

        # Create __init__.py if it doesn't exist in template
        init_file = new_module_dir / "__init__.py"
        if not init_file.exists():
            init_file.touch()

        print(f"Module '{module_name}' created successfully.")
        print("Don't forget to register your new router in djast/urls.py!")
    except Exception as e:
        print(f"Error creating module: {e}")
