import subprocess
import xml.etree.ElementTree as ET
import google.generativeai as genai
import os
import shutil

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

def decode_apk(apk_filename):
    try:
        subprocess.run(['java', '-jar', 'apktool.jar' , 'd' ,  apk_filename, '-o', f"{apk_filename}-decoded"], check=True)
        print(f"APK decoded successfully: {apk_filename}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while trying to decode the APK: {e}")

def parse_manifest(apk_path):
    try:
        tree = ET.parse(f'{apk_path}-decoded/AndroidManifest.xml')
        root = tree.getroot()
        
        permissions = [elem.attrib['{http://schemas.android.com/apk/res/android}name'] for elem in root.findall('uses-permission')]
        services = [elem.attrib['{http://schemas.android.com/apk/res/android}name'] for elem in root.findall('application/service')]
        receivers = [elem.attrib['{http://schemas.android.com/apk/res/android}name'] for elem in root.findall('application/receiver')]
        intents = [elem.attrib['{http://schemas.android.com/apk/res/android}name'] for elem in root.findall('.//intent-filter/action')]
        
        manifest_data = {
            "Permissions": permissions,
            "Services": services,
            "Broadcast Receivers": receivers,
            "Intents": intents
        }
        
        return manifest_data
    except Exception as e:
        print(f"An error occurred while parsing the manifest file: {e}")
        return {}

def analyze_manifest_with_ai(manifest_data , appinfo):
    model = genai.GenerativeModel('gemini-1.5-flash')
    safe = [
    {
        "category": "HARM_CATEGORY_HARASSMENT",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_HATE_SPEECH",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
        "threshold": "BLOCK_NONE",
    },
]
    prompt = (
        "I'm analyzing the AndroidManifest data from an APK. This app is about "
        f"{appinfo}. Please help me identify any potentially suspicious permissions, services, or components that could indicate malicious behavior or potential security risks. "
        "For each item you find, please explain why it might be concerning. for the safety for user "
        
        "Here's the manifest data: "
        f"Permissions:\n{manifest_data.get('Permissions', [])}\n\n"
        f"Services:\n{manifest_data.get('Services', [])}\n\n"
        f"Broadcast Receivers:\n{manifest_data.get('Broadcast Receivers', [])}\n\n"
        f"Intents:\n{manifest_data.get('Intents', [])}\n"

        "Please provide your analysis in a concise and informative way."
    )
    try:
        response = model.generate_content(prompt,
        generation_config=genai.types.GenerationConfig(
            max_output_tokens=10000,
            temperature=0.7) , safety_settings=safe)
        
        return response.candidates[0].content.parts[0]
    except Exception as e:
        print(f"An error occurred while calling the Gemini API: {e}")
        return "Error: Unable to analyze manifest with AI."


if __name__ == "__main__":
    apps = get_installed_apps()
    
    print("Installed apps:")
    for index, app in enumerate(apps, start=1):
        print(f"{index} - {app}")
    
    try:
        choice = int(input("Enter the number of the app you want to pull: "))
        
        if 1 <= choice <= len(apps):
            selected_app = apps[choice - 1]
            print(f"You selected: {selected_app}")

            apk_path = get_app_path(selected_app)
            
            if apk_path:
                apk_filename = pull_apk(apk_path, selected_app)
                
                if apk_filename:
                    decode_apk(apk_filename)
                    manifest_data = parse_manifest(apk_filename)
                    appinfo = input("Enter the app details -> ")
                    
                    if manifest_data:
                        analysis = analyze_manifest_with_ai(manifest_data , appinfo)
                        print(analysis)
                  
                        
                        # Write analysis to a file
                        with open( f"{apk_filename}.txt", 'w') as file:
                            file.write(analysis)
                        
                              
                        # Remove the pulled APK file
                        os.remove(apk_filename)
                        
                        # Remove the decoded APK directory
                        decoded_dir = f"{apk_filename}-decoded"
                        if os.path.exists(decoded_dir):
                            shutil.rmtree(decoded_dir)
                        
                        os.remove(f"{apk_filename}.txt")
                        
        else:
            print("Invalid choice. Please select a number from the list.")
    except ValueError:
        print("Invalid input. Please enter a number.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
