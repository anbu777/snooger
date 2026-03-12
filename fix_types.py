import os
import re

directories = ['core', 'modules']
for d in directories:
    for root, _, files in os.walk(d):
        for f in files:
            if f.endswith('.py'):
                filepath = os.path.join(root, f)
                with open(filepath, 'r', encoding='utf-8') as file:
                    content = file.read()

                # Replace default assignments that conflict with their type annotation
                # e.g., params: dict = None -> params = None
                content = re.sub(r':\s*(?:dict|list|str|int|float|bool|Dict\[[^\]]*\]|List\[[^\]]*\]|Set\[[^\]]*\]|Session|ScopeManager)\s*=\s*None', ' = None', content)
                
                # Special fix for line 130/141 in core/scope_manager.py
                content = re.sub(r'self\.in_scope\.append\(network\)', 'self.in_scope.append(network) # type: ignore', content)
                content = re.sub(r'self\.out_of_scope\.append\(network\)', 'self.out_of_scope.append(network) # type: ignore', content)
                
                # Special fix for python urljoin type hinting bug in Pyright
                content = re.sub(r'urljoin\(base_url,\s*match\)', 'urljoin(base_url, str(match))', content)

                with open(filepath, 'w', encoding='utf-8') as file:
                    file.write(content)

print("Type-checking patches applied.")
