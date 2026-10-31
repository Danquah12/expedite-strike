"""Fix the broken os.path.join calls - add missing closing parentheses."""
import re
import os

app_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")

with open(app_py, "r", encoding="utf-8") as f:
    content = f.read()

# The previous script turned:
#   "/opt/vuln_intel/app/something"  ->  os.path.join(_WIN_APP_DIR, "something"
#   "/opt/vuln_intel/something"      ->  os.path.join(_WIN_PROJECT_ROOT, "something"
# 
# The closing " was part of the original string and is still there,
# but the closing ) for os.path.join is missing.
# We need to find patterns like: os.path.join(_WIN_APP_DIR, "...") and add )
# or os.path.join(_WIN_PROJECT_ROOT, "...") and add )

# Fix pattern: os.path.join(_WIN_APP_DIR, "...text..."  ->  os.path.join(_WIN_APP_DIR, "...text...")
# Also handles single quotes
content = re.sub(
    r'os\.path\.join\((_WIN_APP_DIR|_WIN_PROJECT_ROOT),\s*("(?:[^"]*)")',
    r'os.path.join(\1, \2)',
    content
)

# Now the above won't add the ) since the replacement is identical...
# The actual issue: the string was "something" and replacement made it os.path.join(X, "something"
# We need:  os.path.join(X, "something")
# So find: os.path.join(..., "...") without a closing paren at the end after the quote

# Let's do it differently - find lines with os.path.join that don't have balanced parens
lines = content.split('\n')
fixed_lines = []
for line in lines:
    if 'os.path.join(_WIN_APP_DIR,' in line or 'os.path.join(_WIN_PROJECT_ROOT,' in line:
        # Count open and close parens in the os.path.join portion
        # Find the os.path.join call and ensure it has a closing )
        # Simple approach: for each os.path.join( occurrence, find the matching string end
        new_line = re.sub(
            r'(os\.path\.join\([^,]+,\s*["\'][^"\']*["\'])([^)])',
            r'\1)\2',
            line
        )
        # Handle case where it's at end of line
        new_line = re.sub(
            r'(os\.path\.join\([^,]+,\s*["\'][^"\']*["\'])$',
            r'\1)',
            new_line
        )
        fixed_lines.append(new_line)
    else:
        fixed_lines.append(line)

content = '\n'.join(fixed_lines)

# Also fix f-string cases like f"...{os.path.join(X, 'blah')}..."  
# These should already work since they have quotes around them

with open(app_py, "w", encoding="utf-8") as f:
    f.write(content)

# Verify
remaining_broken = 0
for i, line in enumerate(content.split('\n'), 1):
    if 'os.path.join(_WIN' in line:
        # Check if the join call has balanced parens
        start = line.index('os.path.join(')
        depth = 0
        closed = False
        for ch in line[start:]:
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    closed = True
                    break
        if not closed:
            print(f"  BROKEN line {i}: {line.strip()}")
            remaining_broken += 1

print(f"Done. Broken os.path.join calls remaining: {remaining_broken}")
