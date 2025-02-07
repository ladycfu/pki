# This script will take two parameters X and Y, where X is the name of the file that contains a list of files to be excluded in the execution of the script, and Y is the path where the execution takes place. This script will recursively traverses all .adoc files, except for those listed in X, from the directory Y. For all link references (i.e. link:<link>) found where the <link> matches the pattern "https://github\.com/A/B/C/<filename>[",where "<filename>" can be any string, write the links (without the '[')  to the screen, and writes unique strings represented by <filename> to uniqueNameList-excluded2.txt. If <link> is a unique file that ends with .cfg, write it to the screen as well, but write it to a different file uniqueNameList-excluded2-cfg.txt instead

import os
import re
import sys

def load_exclusion_list(file_path):
    """Load the list of files to be excluded."""
    try:
        with open(file_path, 'r') as file:
            return set(line.strip() for line in file if line.strip())
    except FileNotFoundError:
        print(f"Exclusion file '{file_path}' not found. Proceeding without exclusions.")
        return set()

def extract_links_and_filenames(file_path):
    """Extract GitHub links and filenames matching the pattern from an AsciiDoc file."""
    pattern = re.compile(r'link:https://github\.com/dogtagpki/pki/wiki/([^\[]+)\[')
    cfg_pattern = re.compile(r'link:([^\s]+\.cfg)')
    found_links = set()
    found_filenames = set()
    cfg_filenames = set()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                matches = pattern.findall(line)
                for match in matches:
                    found_links.add(f"https://github.com/dogtagpki/pki/wiki/{match}")
                    found_filenames.add(match)
                
                cfg_matches = cfg_pattern.findall(line)
                for cfg_match in cfg_matches:
                    print(f".cfg reference found: {cfg_match}")
                    cfg_filenames.add(cfg_match)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    
    return found_links, found_filenames, cfg_filenames

def process_directory(base_path, exclusion_list):
    """Recursively process .adoc files in the given directory, excluding specified files."""
    unique_filenames = set()
    cfg_filenames = set()
    
    for root, _, files in os.walk(base_path):
        for file in files:
            if file.endswith(".adoc") and file not in exclusion_list:
                file_path = os.path.join(root, file)
                print(f"Processing: {file_path}")
                found_links, found_filenames, found_cfg_filenames = extract_links_and_filenames(file_path)
                
                for link in found_links:
                    print(link)
                
                unique_filenames.update(found_filenames)
                cfg_filenames.update(found_cfg_filenames)
    
    return unique_filenames, cfg_filenames

def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py <exclusion_file> <directory>")
        sys.exit(1)
    
    exclusion_file = sys.argv[1]
    directory = sys.argv[2]
    
    exclusion_list = load_exclusion_list(exclusion_file)
    unique_filenames, cfg_filenames = process_directory(directory, exclusion_list)
    
    with open("uniqueNameList-excluded2.txt", "w", encoding="utf-8") as outfile:
        for name in sorted(unique_filenames):
            outfile.write(name + "\n")
    
    with open("uniqueNameList-excluded2-cfg.txt", "w", encoding="utf-8") as outfile:
        for name in sorted(cfg_filenames):
            outfile.write(name + "\n")

if __name__ == "__main__":
    main()

