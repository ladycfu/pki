# create a new Python script that works on Linux.  This script will take two input parameters X and Y. X and Y are directory paths. For each .adoc file listed in uniqueLists.txt, if it does not already exist in the directory path Y, then copy the matching file with extension ".asciidoc" from directory X to directory Y and rename it with the extension ".adoc

import os
import shutil
import sys

def copy_missing_adoc_files(source_dir, target_dir):
    # Check if uniqueLinks.txt exists
    if not os.path.exists('uniqueLinks.txt'):
        print("Error: uniqueLinks.txt not found in the current directory.")
        return

    # Read unique links from uniqueLinks.txt
    with open('uniqueLinks.txt', 'r', encoding='utf-8') as file:
        unique_links = [line.strip() for line in file if line.strip()]

    # Ensure the source and target directories exist
    if not os.path.exists(source_dir):
        print(f"Error: Source directory '{source_dir}' does not exist.")
        return

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    # Process each link in uniqueLinks.txt
    for link in unique_links:
        source_file = os.path.join(source_dir, link.replace('.adoc', '.asciidoc'))
        target_file = os.path.join(target_dir, link)

        if os.path.exists(source_file):
            if not os.path.exists(target_file):
                shutil.copyfile(source_file, target_file)
                print(f"Copied and renamed: {source_file} -> {target_file}")
            else:
                print(f"File already exists in target: {target_file}")
        else:
            print(f"Source file does not exist: {source_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <source_directory> <target_directory>")
    else:
        source_directory = sys.argv[1]
        target_directory = sys.argv[2]
        copy_missing_adoc_files(source_directory, target_directory)

