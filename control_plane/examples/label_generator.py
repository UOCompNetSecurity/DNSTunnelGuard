import csv
import os
import base64
import random
import string

def generate_obvtunneling_labels (path : str) -> None:
    # Create and add 90 obvious tunneling labels to the csv at "path" with the obvioustunneling class
    csv_file = open(path, 'a')
    csv_writer = csv.writer(csv_file)
    for i in range(0, 90):
        label = base32_label()
        csv_writer.writerow([label, "obvious_tunneling"])
    csv_file.close()

def base32_label() -> str:
    length = random.randint(4, 25)
    return base64.b32encode(os.urandom(length)).decode().strip("=")

def generate_evatunneling_labels (path : str) -> None:
    # Create and add 90 evasive tunneling labels to the csv at "path" with the evasivetunneling class
    csv_file = open(path, 'a')
    csv_writer = csv.writer(csv_file)
    for i in range(0, 90):
        label = evasive_label()
        csv_writer.writerow([label, "evasive_tunneling"])
    csv_file.close()

def evasive_label():
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(random.choice(alphabet) for i in range(random.randint(5, 10)))

def generate_benign_labels (path: str) -> None:
    # Create and add 90 benign labels to the csv at "path" with the benign class
    benign_labels = [
    "www",
    "mail",
    "smtp",
    "imap",
    "poptartsareverygooo",
    "webmail",
    "login",
    "auth",
    "account",
    "accounts",
    "user",
    "users",
    "profile",
    "dashboard",
    "admin",
    "portal",
    "console",
    "support",
    "help",
    "status",
    "api",
    "cdn",
    "static",
    "assets",
    "images",
    "img",
    "media",
    "video",
    "videos",
    "download",
    "uploads",
    "files",
    "docs",
    "documentation",
    "blog",
    "news",
    "forum",
    "community",
    "search",
    "query",
    "index",
    "home",
    "landing",
    "main",
    "secure",
    "private",
    "public",
    "internal",
    "external",
    "intranet",
    "vpn",
    "remote",
    "gateway",
    "proxy",
    "edge",
    "router",
    "server",
    "servers",
    "host",
    "hosts",
    "node",
    "nodes",
    "cluster",
    "service",
    "services",
    "backend",
    "frontend",
    "client",
    "clients",
    "app",
    "apps",
    "mobile",
    "desktop",
    "cloud",
    "storage",
    "backup",
    "archive",
    "data",
    "database",
    "db",
    "mysql",
    "postgres",
    "redis",
    "cache",
    "queue",
    "metrics",
    "monitor",
    "monitoring",
    "health",
    "heartbeat"]

    csv_file = open(path, 'w')
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["label", "class"])
    for label in benign_labels:
        csv_writer.writerow([label, "benign"])
    csv_file.close()