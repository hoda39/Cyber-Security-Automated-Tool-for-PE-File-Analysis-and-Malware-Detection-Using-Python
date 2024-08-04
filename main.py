import yara
import tkinter as tk
from tkinter import filedialog
import customtkinter as ctk
from CTkMessagebox import CTkMessagebox
import os
from datetime import datetime
from config import *
from utils import virustotal_api
from StaticMalwareAnalysis import StaticMalwareAnalysis
import subprocess
from PIL import Image, ImageTk

filepath = ""


def open_file():
    # Open a file dialog and store the selected file path
    file_path = filedialog.askopenfilename()
    global filepath
    filepath = file_path
    if file_path:
        # You can perform further operations with the selected file here
        label1.configure(text=f"Selected file: {file_path}")
    return file_path


def printHxDinFile(filePath):
    if filepath != "":
        with open(filePath, "rb") as f:
            content = f.read().hex()
        filename = "report.txt"
        with open(filename, "w") as file:
            # Write the string data to the file
            file.write(content)


def modifyHash():
    if filepath != "":
        with open(filepath, "rb") as file:
            content = file.read().hex()
            beforeCon = content[: len(content) - 32 : -1]
            beforeCon = beforeCon[::-1]
            s = StaticMalwareAnalysis(
                os.path.join(config["malware-sample-folder"], filepath)
            )
            hashValueBefore = s.get_sha256sum()
        label3.configure(text=hashValueBefore)
        # C:/Users/Azouz/Downloads/PracticalMalwareAnalysis-Labs-Copy.exe
        print("-----------------------------------------")
        print(filepath)
        with open(filepath, "wb") as file:
            file.write(bytes.fromhex(content + "aa11"))
        with open(filepath, "rb") as file:
            content = file.read().hex()
            newCon = content[: len(content) - 32 : -1]
            newCon = newCon[::-1]
            hashValueAfter = s.get_sha256sum()
        label5.configure(text=hashValueAfter)
        CTkMessagebox(
            title="Hash Changing",
            message="Hash Value Before : "
            + label3.cget("text")
            + "\n\nHash Value After : "
            + label5.cget("text"),
            width=500,
            icon_size=[50, 50],
        )


packer_text = ""


def Detect_packer():
    # Load the compiled YARA ruleset path
    if filepath != "":
        ruleset_file = "packer.yar"
        rules = yara.compile(ruleset_file)
        global packer_text
        # Scan the input file for matches
        matches = rules.match(filepath)

        if matches:
            for match in matches:
                label = ctk.CTkLabel(root, text=f"Packer: {match.rule}")
                dynamic_labels.append(label)
                packer_text += f"{match.rule}, "
        else:
            label = ctk.CTkLabel(root, text="No packer detected")
            packer_text = "No packer detected"
            dynamic_labels.append(label)
        CTkMessagebox(
            title="Packer Detect",
            message="Packers:\n" + packer_text.rstrip(" ,\n"),
            width=500,
            icon_size=[50, 50],
        )


def startScan():
    if filepath != "":
        s = StaticMalwareAnalysis(
            os.path.join(config["malware-sample-folder"], filepath)
        )
        global packer_text
        # file_name = s.create_directory()
        command = f"strings.exe -n 6 {filepath} > strings.txt"
        subprocess.run(command, shell=True, check=True)
        res = s.extractPEINFO()
        filename = "report.txt"
        with open(filename, "w") as file:
            file.write("Architecture : " + res["archirecture"] + "\n\n")
            file.write("Hash Value : " + res["sha256_hash"] + "\n\n")
            file.write("Sections : \n\n")
            for i in range(len(res["sections"])):
                file.write(str(res["sections"][i]))
                file.write("\n\n")
            file.write("Malicious API : \n")
            for i in range(len(res["malicious_api"])):
                file.write(str(res["malicious_api"][i]))
                file.write("\n\n")
            if packer_text != "":
                file.write("Packers : \n")
                file.write(packer_text.rstrip(" ,\n"))
                file.write("\n\n")
        file.close()


ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

root = ctk.CTk()
root.geometry("800x400+700+300")
root.title("Static Analysis")
root.configure(bg="#24272e")
root.resizable(False, False)

background_image = Image.open(
    "C:\\Users\\Azouz\\Downloads\\360_F_358108785_rNJtmort9m65M3pft5swd7lnKJcTCB8u.jpg"
)  # Replace with your image path
background_image = background_image.resize((800, 400))
background_image = ImageTk.PhotoImage(background_image)
background_label = tk.Label(root, image=background_image)
background_label.place(x=0, y=0, relwidth=1, relheight=1)


dynamic_labels = []
label1 = ctk.CTkLabel(
    root, text="No File Selected", fg_color="#25619d", font=("Helvetica", 12, "bold")
)
label1.pack(pady=5)

selectFileButton = ctk.CTkButton(
    root, bg_color="#21588e", text="Select a File", command=open_file
)
selectFileButton.pack(pady=20)

modifyingHash = ctk.CTkButton(
    root, bg_color="#1c4973", text="Modify Hash", command=modifyHash
)
modifyingHash.pack(pady=20)


checkPackers = ctk.CTkButton(
    root, text="Check Packers", bg_color="#16385b", command=Detect_packer
)
checkPackers.pack(pady=20)


scanButton = ctk.CTkButton(
    root, bg_color="#1d4873", text="Scan PE File", command=startScan
)
scanButton.pack(pady=20)


label2 = ctk.CTkLabel(
    root, text="Before Modifying Hash", font=("Helvetica", 12, "bold")
)
label3 = ctk.CTkLabel(root, text="", font=("Helvetica", 12, "bold"))
label4 = ctk.CTkLabel(root, text="After Modifying Hash", font=("Helvetica", 12, "bold"))
label5 = ctk.CTkLabel(root, text="", font=("Helvetica", 12, "bold"))
label6 = ctk.CTkLabel(root, text="Packers", font=("Helvetica", 12, "bold"))
root.mainloop()
