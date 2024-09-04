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

def decode_apk(apk_filename):
    try:
        subprocess.run(['java', '-jar', 'apktool.jar', 'd', apk_filename, '-o', f"{apk_filename}-decoded"], check=True)
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

def analyze_manifest_with_ai(manifest_data, appinfo):
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

        "Please provide your analysis in a concise and informative way.In simple 100 word paragraph withour any special character"
    )
    try:
        response = model.generate_content(prompt,
        generation_config=genai.types.GenerationConfig(
            max_output_tokens=10000,
            temperature=0.7) , safety_settings=safe)
        
        return response.candidates[0].content.parts[0].text
    except Exception as e:
        print(f"An error occurred while calling the Gemini API: {e}")
        return "Error: Unable to analyze manifest with AI."

def on_analyze():
    try:
        choice = int(entry.get())
        if 1 <= choice <= len(apps):
            selected_app = apps[choice - 1]
            apk_path = get_app_path(selected_app)
            if apk_path:
                apk_filename = pull_apk(apk_path, selected_app)
                if apk_filename:
                    decode_apk(apk_filename)
                    manifest_data = parse_manifest(apk_filename)
                    appinfo = app_info_entry.get()
                    if manifest_data:
                        analysis = analyze_manifest_with_ai(manifest_data, appinfo)
                        result_text.delete(1.0, tk.END)
                        result_text.insert(tk.END, analysis)
                        # with open(f"{apk_filename}.txt", 'w') as file:
                        #     file.write(str(analysis))
                        os.remove(apk_filename)
                        decoded_dir = f"{apk_filename}-decoded"
                        if os.path.exists(decoded_dir):
                            shutil.rmtree(decoded_dir)
        else:
            messagebox.showerror("Invalid choice", "Please select a number from the list.")
    except ValueError:
        messagebox.showerror("Invalid input", "Please enter a number.")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")

def show_static_analysis(apps):
    clear_frame()

    title_label = tk.Label(main_frame, text="Static Analysis - Android APK Analyzer", font=("Arial", 16))
    title_label.pack(pady=10)

    scroll_text = scrolledtext.ScrolledText(main_frame, width=100, height=20 , font = ('Arial' , 12), padx=10, pady=10)
    scroll_text.pack(padx=20, pady=20 , ipadx=10 , ipady=10)

    for index, app in enumerate(apps, start=1):
        scroll_text.insert(tk.END, f"{index} - {app}\n")

    input_frame = tk.Frame(main_frame )
    input_frame.pack(pady=20)

    index_label = tk.Label(input_frame, text="Enter the app index:" , font=('Arial' , 16))
    index_label.pack(side=tk.LEFT)

    global entry
    entry = tk.Entry(input_frame)
    entry.pack(side=tk.LEFT, padx=10)

    app_info_label = tk.Label(input_frame, text="Enter app details:" , font=('Arial' , 16))
    app_info_label.pack(side=tk.LEFT, padx=5)

    global app_info_entry
    app_info_entry = tk.Entry(input_frame)
    app_info_entry.pack(side=tk.LEFT) 

    analyze_button = tk.Button(main_frame, text="Analyze", command=on_analyze)
    analyze_button.pack(pady=10)

    back_button = tk.Button(main_frame, text="Back", command=show_initial_page)
    back_button.pack(pady=10)

    global result_text
    result_text = scrolledtext.ScrolledText(main_frame, width=200, height=100, font=("Arial", 16)  ,padx=10, pady=10)
    result_text.pack(padx=20, pady=20)

    result_text.configure(wrap=tk.WORD, relief=tk.GROOVE, borderwidth=2)
    result_text.tag_configure("center", justify="center")
    result_text.insert(tk.END, "Analysis Results:\n", "center")

def show_dynamic_analysis():
    clear_frame()

    title_label = tk.Label(main_frame, text="Dynamic Analysis - Android APK Analyzer", font=("Arial", 16))
    title_label.pack(pady=40)

    info_label = tk.Label(main_frame, text="Work in Progress", font=("Arial", 14))
    info_label.pack(pady=10)

    back_button = tk.Button(main_frame, text="Back", command=show_initial_page)
    back_button.pack(pady=10)

def show_initial_page():
    clear_frame()

    main_label = tk.Label(main_frame, text="Welcome to APKAnalyzer", font=("Arial", 36))
    main_label.pack(pady=40)

    title_label = tk.Label(main_frame, text="Choose Analysis Type", font=("Arial", 16))
    title_label.pack(pady=30)

    button_frame = tk.Frame(main_frame)
    button_frame.pack(pady=20)

    static_button = tk.Button(button_frame, text="Static Analysis", command=lambda: show_static_analysis(apps))
    static_button.pack(side=tk.LEFT, padx=10)

    dynamic_button = tk.Button(button_frame, text="Dynamic Analysis", command=show_dynamic_analysis)
    dynamic_button.pack(side=tk.LEFT, padx=10)

def clear_frame():
    for widget in main_frame.winfo_children():
        widget.destroy()

root = tk.Tk()
root.title("Android APK Analyzer")
root.geometry("1500x1000")

main_frame = tk.Frame(root)
main_frame.pack(fill=tk.BOTH, expand=True)


if __name__ == "__main__":
    apps = get_installed_apps()
    if apps:
        show_initial_page()
    else:
        print("No apps found or unable to connect to the device.")

    root.mainloop()
