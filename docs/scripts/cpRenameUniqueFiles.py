import os
import shutil
import sys

def copy_and_rename_files(source_dir, target_dir):
    """
    Copies files listed in uniqueNameList.txt from the source directory to the target directory,
    changing their file extension from .asciidoc to .adoc.

    :param source_dir: Path to the source directory.
    :param target_dir: Path to the target directory.
    """
    list_file = "uniqueNameList.txt"

    # Check if uniqueNameList.txt exists
    if not os.path.exists(list_file):
        print(f"Error: {list_file} not found in the current directory.")
        sys.exit(1)

    # Read file names from uniqueNameList.txt
    with open(list_file, 'r') as file:
        file_names = [line.strip() for line in file.readlines()]

    # Ensure target directory exists
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    # Process and copy files
    for file_name in file_names:
        source_path = os.path.join(source_dir, f"{file_name}.asciidoc")
        target_path = os.path.join(target_dir, f"{file_name}.adoc")

        if os.path.exists(source_path):
            shutil.copy(source_path, target_path)
            print(f"Copied and renamed: {source_path} -> {target_path}")
        else:
            print(f"Warning: {file_name}.asciidoc not found in {source_dir}.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 copy_and_rename_files.py <source_dir> <target_dir>")
        sys.exit(1)

    source_directory = sys.argv[1]
    target_directory = sys.argv[2]

    copy_and_rename_files(source_directory, target_directory)


