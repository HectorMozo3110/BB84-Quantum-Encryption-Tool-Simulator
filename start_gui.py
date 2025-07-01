# start_gui.py
import sys
import os

# Add the root path of the project
root_path = os.path.dirname(__file__)
if root_path not in sys.path:
    sys.path.insert(0, root_path)

# Now import using full path from root
try:
    from gui.bb84_gui import main
    if __name__ == '__main__':
        main()
except Exception as e:
    print("❌ Failed to launch the GUI:", str(e))
    sys.exit(1)

