import subprocess
import xml.etree.ElementTree as ET
import google.generativeai as genai
import os
import shutil
import tkinter as tk
from tkinter import scrolledtext, messagebox

# Configure the API key for Google Generative AI
genai.configure(api_key="AIzaSyC5NMftqNr1LeLSxPRDvfinai4LN5YpplQ")

def get_installed_apps():
    try:
        result = subprocess.run(['adb', 'shell', 'pm', 'list', 'packages'], capture_output=True, text=True, check=True)
        packages = [line.split(":")[1] for line in result.stdout.splitlines()]
        return packages
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while trying to list installed packages: {e}")
        return []

def get_app_path(package_name):
    try:
        result = subprocess.run(['adb', 'shell', 'pm', 'path', package_name], capture_output=True, text=True, check=True)
        apk_path = result.stdout.split(':')[1].strip()
        return apk_path
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while trying to get the path for {package_name}: {e}")
        return None

def pull_apk(apk_path, package_name):
    try:
        filename = f"{package_name.split('.')[-1]}.apk"
        subprocess.run(['adb', 'pull', apk_path, filename], check=True)
        print(f"APK for {package_name} pulled successfully: {filename}")
        return filename
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while trying to pull the APK for {package_name}: {e}")
        return None


