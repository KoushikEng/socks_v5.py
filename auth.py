"""
Authentication module for SOCKSv5 proxy server.
"""

import json
import logging
import os
from typing import Dict

logger = logging.getLogger(__name__)


class AuthenticationManager:
    """
    Manages username/password authentication for SOCKS5 proxy server.
    
    Supports reading user credentials from a JSON file.
    """
    
    def __init__(self, auth_file_path: str = None):
        """
        Initialize authentication manager.
        
        Args:
            auth_file_path: Path to JSON file with username:password pairs
        """
        self.auth_file_path = auth_file_path
        self.users: Dict[str, str] = {}
        self._load_users()
    
    def _load_users(self):
        """Load users from authentication file."""
        if not self.auth_file_path or not os.path.exists(self.auth_file_path):
            logger.warning(f'Authentication file not found: {self.auth_file_path}')
            self.users = {}
            return
        
        try:
            with open(self.auth_file_path, 'r') as f:
                self.users = json.load(f)
            logger.info(f'Loaded {len(self.users)} users from {self.auth_file_path}')
        except json.JSONDecodeError as e:
            logger.error(f'Invalid JSON in authentication file: {e}')
            self.users = {}
        except Exception as e:
            logger.error(f'Error loading authentication file: {e}')
            self.users = {}
    
    def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate a user with username and password.
        
        Args:
            username: Username to authenticate
            password: Password to verify
            
        Returns:
            bool: True if authentication successful, False otherwise
        """
        if not self.users:
            # No users configured, authentication is disabled
            logger.debug('No users configured, authentication disabled')
            return True
        
        if username not in self.users:
            logger.warning(f'Authentication failed: user not found: {username}')
            return False
        
        if self.users[username] != password:
            logger.warning(f'Authentication failed: invalid password for user: {username}')
            return False
        
        logger.debug(f'Authentication successful for user: {username}')
        return True
    
    def add_user(self, username: str, password: str) -> bool:
        """
        Add a new user to the authentication database.
        
        Args:
            username: Username to add
            password: Password for the user
            
        Returns:
            bool: True if user added successfully, False otherwise
        """
        if not username or not password:
            logger.error('Cannot add user: username and password must not be empty')
            return False
        
        if username in self.users:
            logger.error(f'Cannot add user: {username} already exists')
            return False
        
        self.users[username] = password
        
        # Save to file
        if self.auth_file_path:
            try:
                with open(self.auth_file_path, 'w') as f:
                    json.dump(self.users, f, indent=2)
                logger.info(f'User {username} added successfully')
                return True
            except Exception as e:
                logger.error(f'Error saving user to file: {e}')
                # Remove from memory if save failed
                del self.users[username]
                return False
        
        return True
    
    def remove_user(self, username: str) -> bool:
        """
        Remove a user from the authentication database.
        
        Args:
            username: Username to remove
            
        Returns:
            bool: True if user removed successfully, False otherwise
        """
        if username not in self.users:
            logger.error(f'Cannot remove user: {username} not found')
            return False
        
        del self.users[username]
        
        # Save to file
        if self.auth_file_path:
            try:
                with open(self.auth_file_path, 'w') as f:
                    json.dump(self.users, f, indent=2)
                logger.info(f'User {username} removed successfully')
                return True
            except Exception as e:
                logger.error(f'Error saving changes to file: {e}')
                return False
        
        return True
    
    def has_users(self) -> bool:
        """
        Check if there are any users configured.
        
        Returns:
            bool: True if users are configured, False otherwise
        """
        return len(self.users) > 0
    
    def get_supported_methods(self) -> list:
        """
        Get list of supported authentication methods based on configuration.
        
        Returns:
            list: List of authentication method codes
        """
        methods = [NO_AUTH]  # Always support NO_AUTH for backward compatibility
        
        if self.has_users():
            methods.append(USERNAME_PASSWORD)
        
        return methods