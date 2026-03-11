"""
Force-reload demo script
This ensures fresh imports
"""
import sys
import importlib

# Clear any cached imports
for module in list(sys.modules.keys()):
    if 'src.ml' in module or 'src.analyzers' in module:
        del sys.modules[module]

# Now run the demo
import subprocess
result = subprocess.run([sys.executable, 'demo_ml_focused.py'] + sys.argv[1:], cwd='.')
sys.exit(result.returncode)
