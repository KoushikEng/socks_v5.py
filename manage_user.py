#!/usr/bin/env python3

"""
Utility script to manage SOCKS5 proxy users.
"""

import argparse
import json
import os
import sys

from config import AUTH_FILE_PATH
from auth import AuthenticationManager

def list_users():
    """List all configured users."""
    auth_manager = AuthenticationManager(AUTH_FILE_PATH)
    
    if not auth_manager.has_users():
        print("No users configured.")
        return
    
    print("Configured users:")
    for username in auth_manager.users:
        print(f"  - {username}")

def add_user(username, password):
    """Add a new user."""
    auth_manager = AuthenticationManager(AUTH_FILE_PATH)
    
    if auth_manager.add_user(username, password):
        print(f"User '{username}' added successfully.")
    else:
        print(f"Failed to add user '{username}'.")
        sys.exit(1)

def remove_user(username):
    """Remove a user."""
    auth_manager = AuthenticationManager(AUTH_FILE_PATH)
    
    if auth_manager.remove_user(username):
        print(f"User '{username}' removed successfully.")
    else:
        print(f"Failed to remove user '{username}'.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Manage SOCKS5 proxy users')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all users')
    
    # Add command
    add_parser = subparsers.add_parser('add', help='Add a new user')
    add_parser.add_argument('username', help='Username')
    add_parser.add_argument('password', help='Password')
    
    # Remove command
    remove_parser = subparsers.add_parser('remove', help='Remove a user')
    remove_parser.add_argument('username', help='Username to remove')
    
    args = parser.parse_args()
    
    if args.command == 'list':
        list_users()
    elif args.command == 'add':
        add_user(args.username, args.password)
    elif args.command == 'remove':
        remove_user(args.username)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()