import customtkinter
from tkinter import *
import tkinter as tk
from tkinter import Canvas, Button, PhotoImage
import os
import hashlib
import csv
from concurrent.futures import ThreadPoolExecutor
import time
#import yara
import datetime
from tkinter import filedialog, Tk

# Global variables
total_files = 0
infected_files = 0
start_time = time.time()
infected_file_paths = []


###################### GUI START ########################
# System setting
customtkinter.set_appearance_mode("Dark")
customtkinter.set_default_color_theme("blue")

# Our app Frame
app = customtkinter.CTk()
app.geometry("720x480")
app.title("Final Year Project")

# Adding UI Element
title = customtkinter.CTkLabel(app, text="Scan Your Computer", font=("Helvetica", 30), padx=30)
title.pack(padx=10, pady=10, anchor="w")



# Quick scan label and button
quick_scan_type_frame = customtkinter.CTkFrame(master=app)  # Create a frame
quick_scan_type_frame.pack(padx=20, pady=20,anchor="center")  # Pack the frame with padding
quick_scan_label = customtkinter.CTkLabel(
    master=quick_scan_type_frame,
    text="Run a quick scan\nCheck the most common malware hiding in your computer",
    font=("Helvetica", 16),
    width=600,  # Adjust width as needed
    justify=tk.LEFT,  # Left-align text within the label
    anchor="w",
)
quick_scan_label.pack(padx=10, pady=5)

# Quick scan button
quick_scan_button = customtkinter.CTkButton(
    master=quick_scan_type_frame, text="Quick Scan", font=("Helvetica", 20), corner_radius=32,hover_color="#4158D0",border_color="#FFCC70",border_width=1, command=lambda:scan_system32()
)
quick_scan_button.place(relx=0.99, rely=0.52, anchor="e")  # Align to the right side

# Custom scan label and button
custom_scan_type_frame = customtkinter.CTkFrame(master=app)  # Create a frame
custom_scan_type_frame.pack(padx=20, pady=20)  # Pack the frame with padding
custom_scan_label = customtkinter.CTkLabel(
    master=custom_scan_type_frame,
    text="Run a custom scan\nChoose which files and folders to check for malware",
    font=("Helvetica", 16),
    width=600,  # Adjust width as needed
    justify=tk.LEFT,  # Left-align text within the label
    anchor="w",
)
custom_scan_label.pack(padx=10, pady=5)
# Custom Scan Button
custom_scan_button = customtkinter.CTkButton(
    master=custom_scan_type_frame, text="Custom Scan", font=("Helvetica", 20),corner_radius=32,hover_color="#4158D0",border_color="#FFCC70",border_width=1, command=lambda: print("Custom Scan Selected")
)
custom_scan_button.place(relx=0.99, rely=0.52, anchor="e")  # Align to the right side

# Full scan label and button
full_scan_type_frame = customtkinter.CTkFrame(master=app)  # Create a frame
full_scan_type_frame.pack(padx=20, pady=20)  # Pack the frame with padding
full_scan_label = customtkinter.CTkLabel(
    master=full_scan_type_frame,
    text="Run a full scan\nCheck your entire computer for malware",
    font=("Helvetica", 16),
    width=600,  # Adjust width as needed
    justify=tk.LEFT,  # Left-align text within the label
    anchor="w",
)
full_scan_label.pack(padx=10, pady=5)
# Full scan Button
full_scan_button = customtkinter.CTkButton(
    master=full_scan_type_frame, text="Full Scan", font=("Helvetica", 20),corner_radius=32,hover_color="#4158D0",border_color="#FFCC70",border_width=1, command=lambda: scan_system32()
)
full_scan_button.place(relx=0.99, rely=0.52, anchor="e")  # Align to the right side

# Cancel Button
def exit_gui():
    app.destroy()

Cancel = customtkinter.CTkButton(app, text="Cancel",font=("Helvetica", 20),corner_radius=32,hover_color="#4158D0",border_color="#FFCC70",border_width=1, command=exit_gui)
Cancel.pack()
######################### GUI END #############################

######################### SYSTEM 32 SCAN ######################
# Function to compute MD5 hash of a file
# Function to compute MD5 hash of a file
def compute_md5(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        data = f.read(4194304)  # Read file in larger chunks (4 MB)
        while data:
            hasher.update(data)
            data = f.read(4194304)
    return hasher.hexdigest()

# Function to compare MD5 hash with the dataset
def compare_md5_with_dataset(file_md5, dataset):
    return file_md5 in dataset

# Function to scan a single file
def scan_single_file(file_path, dataset):
    global infected_files

    try:
        file_md5 = compute_md5(file_path)
        is_infected = compare_md5_with_dataset(file_md5, dataset)
        if is_infected:
            infected_files += 1
            print(f"File '{file_path}' is potentially malicious!")
            infected_file_paths.append(file_path)
        else:
            print(f"File '{file_path}' seems clean.")
    except PermissionError as e:
        print(f"Permission error: {e}. Skipping file: {file_path}")

# Function to scan the System32 folder
def scan_system32():
    global total_files

    system32_path = os.path.join(os.environ['SystemRoot'], 'System32')
    file_list = []

    for root_dir, _, files in os.walk(system32_path):
        for file in files:
            file_path = os.path.join(root_dir, file)
            file_list.append(file_path)

    num_threads = os.cpu_count() * 2
    batch_size = 50  # Experiment with different batch sizes

    total_files = len(file_list)
    processed_files = 0

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        dataset = load_dataset('known_signature.csv')
        for i in range(0, total_files, batch_size):
            batch_files = file_list[i:i + batch_size]
            executor.map(scan_single_file, batch_files, [dataset] * len(batch_files))

            processed_files += len(batch_files)
            progress_percentage = (processed_files / total_files) * 100
            print(f"Scanning progress: {progress_percentage:.2f}% ({processed_files}/{total_files})")

    print_scan_results()

# Function to load the dataset from a CSV file
def load_dataset(dataset_file):
    dataset = set()
    with open(dataset_file, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            dataset.add(row['md5'])
    return dataset

# Function to print scan results
def print_scan_results():
    print(f"Total files: {total_files}")
    print(f"Infected files: {infected_files}")
    print(f"Infected file paths: {infected_file_paths}")
    print(f"Scan duration: {time.time() - start_time:.2f} seconds")


#########################  SYSTEM 32 END ######################


# Run app
app.mainloop()