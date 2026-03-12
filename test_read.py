import json

with open('pyright_errors.json', 'rb') as f:
    content = f.read()

# Try to decode
try:
    text = content.decode('utf-16le')
except:
    text = content.decode('utf-8', errors='ignore')

# Strip any weird leading characters (like BOM)
start_idx = text.find('{')
if start_idx != -1:
    text = text[start_idx:]

data = json.loads(text)

counts = {}
for err in data.get('generalDiagnostics', []):
    f_name = err['file'].split('snooger')[1]
    msg = err['message']
    
    # Group by message to see the main issues
    if msg not in counts:
        counts[msg] = []
    counts[msg].append(f"{f_name}:{err['range']['end']['line']}")

# Print top 15 most common errors
sorted_errors = sorted(counts.items(), key=lambda x: len(x[1]), reverse=True)
for msg, locations in sorted_errors[:15]:
    print(f"[{len(locations)} times] {msg}")
    print(f"  Examples: {', '.join(locations[:3])}")
    print()
