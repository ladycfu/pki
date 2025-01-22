# write a python code that works on Linux.  This python code will do the following in the executing directory: it will recursively traverse all asciidoc files ending with ".adoc". For each ".adoc" file it finds, it will find and replace all occurrences of "https://github.com/dogtagpki/pki/wiki" with "../../wiki"

import os
import re

# Function to process a single .adoc file
def process_adoc_file(filepath):
    with open(filepath, 'r') as file:
        content = file.read()

    # Replace all occurrences of the specified URL with "../../wiki"
    updated_content = re.sub(
        r'https://github.com/dogtagpki/pki/wiki',
        r'../../wiki',
        content
    )

    # Write the updated content back to the file
    with open(filepath, 'w') as file:
        file.write(updated_content)

# Function to recursively traverse and process .adoc files
def process_directory(directory):
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith(".adoc"):
                filepath = os.path.join(root, filename)
                print(f"Processing {filepath}...")
                process_adoc_file(filepath)

# Main script
if __name__ == "__main__":
    # Get the current working directory
    current_directory = os.getcwd()

    # Process all .adoc files in the directory recursively
    process_directory(current_directory)

    print("All .adoc files have been processed.")

