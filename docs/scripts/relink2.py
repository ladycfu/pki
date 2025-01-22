# Write a new python code that works on a Linux system.  This code will do the following in the executing directory: It will go through all the files ending with ".adoc" and add the suffix ".adoc" to all link references (e.g. from link:abcde[here] to link:abcde.adoc[here]) except for the two cases: 1. the links are full urls that begin with "http" 2. the links already end with .adoc

import os
import re

def update_adoc_links():
    # Define the regex pattern to match link references
    link_pattern = re.compile(r'(link:([^\s\[]+)(\[[^\]]*\]))')

    # Get the current directory
    current_dir = os.getcwd()

    for file_name in os.listdir(current_dir):
        # Process only .adoc files
        if file_name.endswith(".adoc"):
            file_path = os.path.join(current_dir, file_name)

            # Read the file content
            with open(file_path, 'r') as file:
                content = file.read()

            # Replace links as per the rules
            def replace_link(match):
                full_match, link_path, link_suffix = match.group(1), match.group(2), match.group(3)
                if link_path.startswith("http") or link_path.endswith(".adoc"):
                    return full_match  # Do not modify
                else:
                    return f"link:{link_path}.adoc{link_suffix}"  # Add .adoc suffix

            updated_content = link_pattern.sub(replace_link, content)

            # Write updated content back to the file if changes were made
            if content != updated_content:
                with open(file_path, 'w') as file:
                    file.write(updated_content)
                print(f"Updated links in: {file_name}")
            else:
                print(f"No changes needed for: {file_name}")

if __name__ == "__main__":
    update_adoc_links()

