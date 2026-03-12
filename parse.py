import sys
import re

text = open('snooger_check.txt', encoding='utf-16le').read()
for line in text.split('\n'):
    if ' - error: ' in line:
        print(line.strip())
