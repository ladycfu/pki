import os
import re

def find_unique_links():
    # Define the regex pattern to match asciidoc link references
    link_pattern = re.compile(r'link:([\w/.-]+\.adoc)')

    # Get all .adoc files in the current directory
    adoc_files = [f for f in os.listdir('.') if os.path.isfile(f) and f.endswith('.adoc')]

    # Set to store unique links
    unique_links = set()

    # Process each .adoc file
    for adoc_file in adoc_files:
        with open(adoc_file, 'r', encoding='utf-8') as file:
            content = file.read()
            # Find all links in the file
            matches = link_pattern.findall(content)
            # Add the matches to the set of unique links
            unique_links.update(matches)

    # Write unique links to the output file
    with open('uniqueLinks.txt', 'w', encoding='utf-8') as output_file:
        for link in sorted(unique_links):  # Sorting for consistent order
            output_file.write(link + '\n')

if __name__ == "__main__":
    find_unique_links()

