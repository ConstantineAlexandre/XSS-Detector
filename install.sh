#!/bin/bash

# Get the path from CheeseBurger.py
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/xss_checker.py"

# Change the CheeseBurger.py file to executable
chmod +x "$SCRIPT_PATH"

# Create a symbolic link in /usr/local/bin
ln -sf "$SCRIPT_PATH" /usr/local/bin/xss_checker

echo "xss_checker has been successfully installed. Now you can run it with the command 'xss_checker' in the terminal."

