Run in the following order:

cd pki/docs
mkdir wiki

cd pki/docs/installation
python3 rExtractUniqueLinks.py
   (or prExtractUniqueLinks.py for print out of traversed files on screen)
output: uniqueNameList.txt

python3 cpRenameUniqueFiles.py pki.wiki pki/docs/wiki
result: 1st level files copied over from pki.wiki and renamed from .asciidoc to .adoc

cd pki/docs/wiki
loop begins
- python3 relnik2.py
result: fixed all local link references to end with .adoc

- python3 uniqueLinks.py
 (or uniqueLinks2.py if want to see more info on screen)

- python 3 cpMissingLinkFiles.py pki.wiki pki/docs/wiki

loop ends

When ready:
- Change all ref links to point to the repo pki/docs/wiki/*
cd pki/docs/installation
python3 rereflink.py

