"""Start the ConfigSentry web app:  python run.py"""

import sys

from configsentry.cli import main

if __name__ == "__main__":
    sys.exit(main(["ui", *sys.argv[1:]]))
