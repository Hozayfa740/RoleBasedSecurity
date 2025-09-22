import tkinter as tk
import os
from tkinter import filedialog, messagebox
from tkinter import Toplevel
import subprocess
import platform
from secure_backend import get_user_statistics
from secure_backend import (
    setup_and_initialize, login_user, register_user, change_user_password,
    encrypt_file, decrypt_file, fetch_logs, get_all_users_with_access,
    update_user_access, delete_user,
    export_users_csv,
    log_action
)

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Manager")
        self.root.geometry("700x650+15+15")
        self.root.configure(bg="#1b1f3b")
        self.username = None
        self.role = None
        self.colors = {
            "primary_bg": "#1b1f3b",
            "secondary_bg": "#2d325a",
            "button_bg": "#4ecca3",
            "button_hover": "#45b393",
            "danger_bg": "#e94560",
            "text_color": "#f1f1f1",
            "header_fg": "#ffffff"
        }

        setup_and_initialize()
        self.login_screen()

    def style_button(self, btn, bg, hover_bg):
        btn.config(bg=bg, fg="white", font=("Arial", 11, "bold"), bd=0, relief="flat", padx=10, pady=6, activebackground=hover_bg)
        btn.bind("<Enter>", lambda e: btn.config(bg=hover_bg))
        btn.bind("<Leave>", lambda e: btn.config(bg=bg))

    def clear_widgets(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def login_screen(self):
        self.clear_widgets()
        tk.Label(self.root, text="🔐 FortiGuard OS", font=("Arial", 26, "bold"), fg=self.colors["header_fg"],
                 bg=self.colors["primary_bg"]).pack(pady=40)

        # Username
        tk.Label(self.root, text="Username", bg=self.colors["primary_bg"], fg=self.colors["text_color"], font=("Arial", 12, "bold")).pack()
        username_entry = tk.Entry(self.root, font=("Arial", 12), width=30)
        username_entry.pack(pady=5)

        # Password
        tk.Label(self.root, text="Password", bg=self.colors["primary_bg"], fg=self.colors["text_color"], font=("Arial", 12, "bold")).pack()
        password_entry = tk.Entry(self.root, show="*", font=("Arial", 12), width=30)
        password_entry.pack(pady=5)

        def login():
            username = username_entry.get()
            password = password_entry.get()
            success, role_or_msg = login_user(username, password)
            if success:
                self.username = username
                self.role = role_or_msg
                log_action(self.username, "Logged In", "")  # Log login here
                self.dashboard()
            else:
                messagebox.showerror("Login Failed", role_or_msg)

        # Buttons
        login_btn = tk.Button(self.root, text="Login", command=login)
        self.style_button(login_btn, self.colors["button_bg"], self.colors["button_hover"])
        login_btn.pack(pady=15)

        register_btn = tk.Button(self.root, text="Register", command=self.register_screen)
        self.style_button(register_btn, self.colors["secondary_bg"], "#3b3f70")
        register_btn.pack()

    def logout(self):
        if self.username:
            log_action(self.username, "Logged Out", "")  # Log logout here
        self.username = None
        self.role = None
        self.login_screen()

    def register_screen(self):
        self.clear_widgets()
        tk.Label(self.root, text="📝 Register", font=("Arial", 24, "bold"), fg=self.colors["header_fg"],
                 bg=self.colors["primary_bg"]).pack(pady=30)

        # Fields
        labels = ["Username", "Password", "Role"]
        entries = []
        for label in labels[:-1]:
            tk.Label(self.root, text=label, bg=self.colors["primary_bg"], fg=self.colors["text_color"], font=("Arial", 12, "bold")).pack()
            e = tk.Entry(self.root, show="*" if label == "Password" else "", font=("Arial", 12), width=30)
            e.pack(pady=5)
            entries.append(e)

        # Role dropdown
        roles = ['admin', 'editor', 'viewer']
        role_var = tk.StringVar(value=roles[0])
        role_menu = tk.OptionMenu(self.root, role_var, *roles)
        role_menu.config(font=("Arial", 11), bg=self.colors["secondary_bg"], fg="white", relief="flat")
        role_menu.pack(pady=5)

        def register():
            username, password = entries[0].get(), entries[1].get()
            role = role_var.get()
            if register_user(username, password, role):
                messagebox.showinfo("Success", "User registered.")
                self.login_screen()
            else:
                messagebox.showerror("Error", "Username already exists.")

        reg_btn = tk.Button(self.root, text="Register", command=register)
        self.style_button(reg_btn, self.colors["button_bg"], self.colors["button_hover"])
        reg_btn.pack(pady=15)

        back_btn = tk.Button(self.root, text="Back", command=self.login_screen)
        self.style_button(back_btn, self.colors["danger_bg"], "#c03945")
        back_btn.pack()

    def dashboard(self):
        self.clear_widgets()
        tk.Label(self.root, text=f"Welcome, {self.username} 🎉", font=("Arial", 20, "bold"),
                 fg=self.colors["header_fg"], bg=self.colors["primary_bg"]).pack(pady=15)

        stats = dict(get_user_statistics())
        stat_text = " | ".join([f"{r.capitalize()}s: {stats.get(r, 0)}" for r in ['admin', 'editor', 'viewer']])
        tk.Label(self.root, text=f"User Stats: {stat_text}", font=("Arial", 13, "italic"),
                 fg=self.colors["text_color"], bg=self.colors["primary_bg"]).pack(pady=5)

        # Buttons List
        buttons = []
        if self.role in ('admin', 'editor'):
            buttons.extend([
                ("Encrypt File 🔒", self.encrypt_screen),
                ("Decrypt File 🔓", self.decrypt_screen)
            ])
        buttons.append(("View File 📄", self.view_file))
        buttons.append(("Change Password 🔑", self.change_password))
        buttons.append(("View Logs 📜", self.view_logs))
        if self.role == 'admin':
            buttons.append(("Manage Users ⚙️", self.manage_users))
        buttons.append(("Logout 🚪", self.logout))  # Use logout method here

        for text, cmd in buttons:
            b = tk.Button(self.root, text=text, command=cmd, width=25)
            self.style_button(b, self.colors["button_bg"], self.colors["button_hover"])
            b.pack(pady=6)

    def encrypt_screen(self):
        if self.role not in ('admin', 'editor'):
            messagebox.showerror("Access Denied", "You do not have permission to encrypt files.")
            return
        filepath = filedialog.askopenfilename()
        if filepath:
            encrypt_file(filepath)
            log_action(self.username, "Encrypted", os.path.basename(filepath))  # Log encryption
            messagebox.showinfo("Encrypted", f"Encrypted: {filepath}.enc")

    def decrypt_screen(self):
        if self.role not in ('admin', 'editor'):
            messagebox.showerror("Access Denied", "You do not have permission to decrypt files.")
            return
        filepath = filedialog.askopenfilename()
        if filepath:
            try:
                decrypt_file(filepath)
                log_action(self.username, "Decrypted", os.path.basename(filepath))  # Log decryption
                messagebox.showinfo("Decrypted", "Decryption Successful")
            except:
                messagebox.showerror("Error", "Decryption failed")

    def change_password(self):
        def update_pw():
            old_pw = old_entry.get()
            new_pw = new_entry.get()
            confirm_pw = confirm_entry.get()

            if not old_pw or not new_pw or not confirm_pw:
                messagebox.showerror("Error", "All fields are required.")
                return
            if new_pw != confirm_pw:
                messagebox.showerror("Error", "New passwords do not match.")
                return

            success, msg = change_user_password(self.username, old_pw, new_pw)
            messagebox.showinfo("Info", msg)
            if success:
                log_action(self.username, "Changed Password", "")  # Log password change
                top.destroy()

        top = tk.Toplevel(self.root)
        top.title("Change Password")
        top.geometry("350x330")
        top.configure(bg=self.colors["primary_bg"])
        top.grab_set()


        tk.Label(
            top, text="Change Your Password",
            font=("Arial", 16, "bold"),
            fg=self.colors["header_fg"],
            bg=self.colors["primary_bg"]
        ).pack(pady=15)

        # Old password
        tk.Label(top, text="Old Password", fg=self.colors["text_color"], bg=self.colors["primary_bg"]).pack(anchor="w", padx=20)
        old_entry = tk.Entry(top, show="*", width=30, font=("Arial", 12))
        old_entry.pack(pady=5)

        # New password
        tk.Label(top, text="New Password", fg=self.colors["text_color"], bg=self.colors["primary_bg"]).pack(anchor="w", padx=20)
        new_entry = tk.Entry(top, show="*", width=30, font=("Arial", 12))
        new_entry.pack(pady=5)

        # Confirm password
        tk.Label(top, text="Confirm Password", fg=self.colors["text_color"], bg=self.colors["primary_bg"]).pack(anchor="w", padx=20)
        confirm_entry = tk.Entry(top, show="*", width=30, font=("Arial", 12))
        confirm_entry.pack(pady=5)

        # Change button
        btn_update = tk.Button(
            top, text="Update Password", command=update_pw,
            bg=self.colors["button_bg"], fg="white", font=("Arial", 12, "bold"), width=20
        )
        btn_update.pack(pady=15)
        self.style_button(btn_update, self.colors["button_bg"], self.colors["button_hover"])

        # Cancel button
        btn_cancel = tk.Button(
            top, text="Cancel", command=top.destroy,
            bg=self.colors["danger_bg"], fg="white", font=("Arial", 10, "bold"), width=15
        )
        btn_cancel.pack()
        self.style_button(btn_cancel, self.colors["danger_bg"], "#c03945")

    def view_logs(self):
        self.clear_widgets()

        # Header
        tk.Label(
            self.root, text="📜 Logs",
            font=("Arial", 24, "bold"),
            fg=self.colors["header_fg"],
            bg=self.colors["primary_bg"]
        ).pack(pady=20)

        try:
            logs = fetch_logs(self.username, self.role)
            print("Fetched logs:", logs)  # Debug print to console
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch logs:\n{e}")
            self.dashboard()
            return

        # Frame with scrollbar
        container = tk.Frame(self.root, bg=self.colors["primary_bg"])
        container.pack(fill="both", expand=True, padx=15, pady=10)

        canvas = tk.Canvas(container, bg=self.colors["primary_bg"], highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.colors["primary_bg"])

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # If no logs found
        if not logs:
            tk.Label(
                scrollable_frame,
                text="No logs found.",
                font=("Arial", 14, "italic"),
                fg="#cccccc",
                bg=self.colors["primary_bg"]
            ).pack(pady=30)
        else:
            # Display each log nicely
            for log in logs:
                user = log[0] if log[0] else "Unknown"
                action = log[1] if log[1] else "Unknown Action"
                filename = log[2] if log[2] else "N/A"
                timestamp = log[3] if log[3] else "Unknown Time"

                # Format timestamp if possible
                if hasattr(timestamp, "strftime"):
                    timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    timestamp = str(timestamp)

                text = f"{timestamp}  |  User: {user}  |  Action: {action}  |  File: {filename}"

                tk.Label(
                    scrollable_frame,
                    text=text,
                    font=("Consolas", 11),
                    fg=self.colors["text_color"],
                    bg=self.colors["primary_bg"],
                    anchor="w",
                    justify="left",
                    padx=10,
                    pady=4,
                    relief="groove",
                    bd=1
                ).pack(fill="x", pady=3, padx=5)

        # Back Button
        back_btn = tk.Button(self.root, text="⬅ Back", command=self.dashboard)
        back_btn.config(
            bg=self.colors["secondary_bg"],
            fg="white",
            font=("Arial", 13, "bold"),
            relief="flat",
            padx=15,
            pady=8,
            activebackground="#3b3f70"
        )
        back_btn.pack(pady=20)
        back_btn.bind("<Enter>", lambda e: back_btn.config(bg="#3b3f70"))
        back_btn.bind("<Leave>", lambda e: back_btn.config(bg=self.colors["secondary_bg"]))

    def manage_users(self):
        self.clear_widgets()
        tk.Label(self.root, text="⚙️ Manage User Access", font=("Arial", 20, "bold"),
                 fg=self.colors["header_fg"], bg=self.colors["primary_bg"]).pack(pady=20)

        users = get_all_users_with_access()
        roles = ['admin', 'editor', 'viewer']
        accesses = ['active', 'blocked']
        self.role_vars = {}
        self.access_vars = {}

        for username, role, access in users:
            frame = tk.Frame(self.root, bg=self.colors["primary_bg"])
            frame.pack(pady=2, padx=10, fill='x')

            tk.Label(frame, text=username, width=15, font=("Arial", 12),
                     bg=self.colors["primary_bg"], fg=self.colors["text_color"]).pack(side="left", padx=5)

            role_var = tk.StringVar(value=role)
            access_var = tk.StringVar(value=access)
            self.role_vars[username] = role_var
            self.access_vars[username] = access_var

            tk.OptionMenu(frame, role_var, *roles).pack(side="left", padx=5)
            tk.OptionMenu(frame, access_var, *accesses).pack(side="left", padx=5)

            if role != 'admin':
                del_btn = tk.Button(frame, text="Delete", command=lambda u=username: self.delete_user(u),
                          bg=self.colors["danger_bg"], fg="white", width=8)
                del_btn.pack(side="left", padx=5)
                self.style_button(del_btn, self.colors["danger_bg"], "#c03945")

        def save_changes():
            for username in self.role_vars:
                role = self.role_vars[username].get()
                access = self.access_vars[username].get()
                update_user_access(username, role, access)
            messagebox.showinfo("Success", "Changes saved.")
            self.dashboard()

        def export_users():
            path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
            if path:
                try:
                    export_users_csv(path)
                    messagebox.showinfo("Success", f"User list exported to:\n{path}")
                except Exception as e:
                    messagebox.showerror("Error", f"Export failed:\n{e}")



        save_btn = tk.Button(self.root, text="Save Changes", command=save_changes,
                  font=("Arial", 12), bg=self.colors["button_bg"], fg="white")
        save_btn.pack(pady=10)
        self.style_button(save_btn, self.colors["button_bg"], self.colors["button_hover"])

        export_users_btn = tk.Button(self.root, text="Export Users to CSV", command=export_users,
                  font=("Arial", 12), bg="#2980b9", fg="white")
        export_users_btn.pack(pady=5)
        self.style_button(export_users_btn, "#2980b9", "#1c6691")


        back_btn = tk.Button(self.root, text="Back", command=self.dashboard,
                  font=("Arial", 12), bg=self.colors["secondary_bg"], fg="white")
        back_btn.pack(pady=10)
        self.style_button(back_btn, self.colors["secondary_bg"], "#3b3f70")

        view_file_btn = tk.Button(self.root, text="View File", command=self.view_file,
                  bg=self.colors["button_bg"], fg="white", width=20)
        view_file_btn.pack(pady=10)
        self.style_button(view_file_btn, self.colors["button_bg"], self.colors["button_hover"])

    def delete_user(self, username):
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete user '{username}'?"):
            success = delete_user(username)
            if success is None:
                # delete_user does not return anything, assume success
                success = True
            if success:
                messagebox.showinfo("Deleted", f"User '{username}' deleted.")
                self.manage_users()
            else:
                messagebox.showerror("Error", "Failed to delete user.")

    def open_file_external(self, filepath):
        try:
            if platform.system() == 'Windows':
                os.startfile(filepath)  # Windows open with default program
            elif platform.system() == 'Darwin':
                subprocess.call(('open', filepath))  # macOS
            else:
                subprocess.call(('xdg-open', filepath))  # Linux
        except Exception as e:
            messagebox.showerror("Error", f"Cannot open file:\n{e}")

    def view_file(self):
        filepath = filedialog.askopenfilename(title="Select file to view")
        if not filepath:
            return
        self.open_file_external(filepath)


if __name__ == '__main__':
    root = tk.Tk()
    app = App(root)
    root.mainloop()
