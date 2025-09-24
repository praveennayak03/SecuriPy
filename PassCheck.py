import re
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk

def check_password_strength(password: str) -> dict:
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long.")
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")
    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Include at least one number.")
    if re.search(r"[!@#$%^&*()]", password):
        score += 1
    else:
        feedback.append("Use at least one special character (!@#$%^&*()).")

    ratings = {
        1: "Very Weak",
        2: "Weak",
        3: "Moderate",
        4: "Strong",
        5: "Very Strong"
    }
    return {
        "score": score,
        "rating": ratings.get(score, "Very Weak"),
        "feedback": feedback
    }

def evaluate_password(event=None):
    pwd = entry.get()
    result = check_password_strength(pwd)

    result_label.config(
        text=f"{result['rating']} ({result['score']}/5)",
        fg=colors.get(result['rating'], "black")
    )

    progress["value"] = result['score'] * 20
    style.configure("Custom.Horizontal.TProgressbar",
                    background=colors[result['rating']])

    if result['feedback']:
        messagebox.showinfo("Suggestions", "\n".join(result['feedback']))
    else:
        messagebox.showinfo("Suggestions", "✅ Looks good! Your password is strong.")

def toggle_password():
    if entry.cget("show") == "":
        entry.config(show="*")
        toggle_btn.config(text="👁")
    else:
        entry.config(show="")
        toggle_btn.config(text="🙈")

# --- UI Setup ---
root = tk.Tk()
root.title("Cyber-Style Password Strength Checker")
root.geometry("600x400")

# Load your local image
bg_img = Image.open("key.jpg")  # <-- Replace with your image file
bg_img = bg_img.resize((1920, 1080))
bg_photo = ImageTk.PhotoImage(bg_img)

bg_label = tk.Label(root, image=bg_photo)
bg_label.place(relx=0, rely=0, relwidth=1, relheight=1)

# Card container
card = tk.Frame(root, bg="#ffffff", bd=2, relief="ridge")
card.place(relx=0.5, rely=0.5, anchor="center", width=480, height=320)

# Title
title = tk.Label(card, text="🔐 Password Strength Checker",
                 font=("Segoe UI", 18, "bold"), bg="#ffffff", fg="#0d1b2a")
title.pack(pady=15)

# Entry + toggle
entry_frame = tk.Frame(card, bg="#ffffff")
entry_frame.pack(pady=5)

entry = tk.Entry(entry_frame, width=28, font=("Segoe UI", 14), show="*")
entry.grid(row=0, column=0, padx=5)

toggle_btn = tk.Button(entry_frame, text="👁", command=toggle_password,
                       bg="#ffffff", relief="flat", font=("Arial", 12))
toggle_btn.grid(row=0, column=1)

# Result label
result_label = tk.Label(card, text="", font=("Segoe UI", 14, "bold"),
                        bg="#ffffff")
result_label.pack(pady=10)

# Progress bar
style = ttk.Style()
style.theme_use("clam")
style.configure("Custom.Horizontal.TProgressbar", thickness=25,
                troughcolor="#e0e0e0", background="#e63946")

progress = ttk.Progressbar(card, orient="horizontal", length=350, mode="determinate",
                           style="Custom.Horizontal.TProgressbar")
progress.pack(pady=15)

# Check button
check_btn = tk.Button(card, text="Check Strength", command=evaluate_password,
                      bg="#0d1b2a", fg="white", font=("Segoe UI", 12, "bold"),
                      relief="flat", padx=12, pady=6, activebackground="#274c77")
check_btn.pack(pady=10)

# Colors for strength
colors = {
    "Very Weak": "#e63946",
    "Weak": "#ff914d",
    "Moderate": "#ffd60a",
    "Strong": "#2ec4b6",
    "Very Strong": "#06d6a0"
}

# Bind Enter key
entry.bind("<Return>", evaluate_password)

root.mainloop()