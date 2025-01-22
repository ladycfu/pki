import os
import re

def find_and_print_unique_links():
    """
    Recursively traverses all .adoc files from the executing directory,
    prints all matching link references to the screen, and writes unique
    strings to uniqueNameList.txt.
    """
    current_directory = os.getcwd()
    unique_strings = set()
    seen_strings = set()

    # Regex pattern to match the desired links
    pattern = re.compile(r'link:https://github\.com/dogtagpki/pki/wiki/([^\[]+)\[')

    # Traverse directories recursively
    for root, _, files in os.walk(current_directory):
        for file_name in files:
            if file_name.endswith('.adoc'):
                file_path = os.path.join(root, file_name)
                with open(file_path, 'r') as file:
                    content = file.read()

                # Find all matches in the file
                matches = pattern.findall(content)
                for match in matches:
                    print(f"Found link: {match}")
                    if match not in seen_strings:
                        unique_strings.add(match)
                        seen_strings.add(match)

    # Write unique strings to a file
    output_file = os.path.join(current_directory, "uniqueNameList.txt")
    with open(output_file, 'w') as file:
        for unique_string in sorted(unique_strings):
            file.write(unique_string + "\n")

    print(f"Unique strings written to {output_file}")

if __name__ == "__main__":
    find_and_print_unique_links()

