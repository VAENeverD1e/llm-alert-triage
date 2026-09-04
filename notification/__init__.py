"""
Notification Package.
Handles webhook notifications and alert outputs to external platforms (e.g. Discord, Slack, SIEM).
"""
from .discord_forwarder import DiscordForwarder

__all__ = ["DiscordForwarder"]
