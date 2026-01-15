#!/usr/bin/env python3
"""
Encryption Viewer - GUI Window for Displaying Encrypted Messages

This module provides a tkinter-based window that displays all chat messages
along with their encrypted versions. It's designed to demonstrate encryption
to instructors during chat sessions.

Architecture:
- Server writes messages to a JSON log file
- Viewer runs as a separate process and monitors the log file
- This avoids macOS threading issues with tkinter
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import json
import os
import time
from datetime import datetime
import subprocess
import sys

# Log file path
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "encryption_log.json")


def write_message_to_log(direction, sender, msg_type, encrypted_data, decrypted_content):
    """
    Write a message to the log file.
    Called by server.py to log messages.

    Args:
        direction: "SENT" or "RECEIVED"
        sender: Name of the sender
        msg_type: "TEXT" or "IMAGE"
        encrypted_data: The raw encrypted Fernet token (bytes or string)
        decrypted_content: The decrypted message text or image description
    """
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Convert encrypted_data to string if needed
    if isinstance(encrypted_data, bytes):
        encrypted_str = encrypted_data.decode('utf-8')
    else:
        encrypted_str = str(encrypted_data)

    message = {
        "timestamp": timestamp,
        "direction": direction,
        "sender": sender,
        "msg_type": msg_type,
        "encrypted_data": encrypted_str,
        "decrypted_content": str(decrypted_content)
    }

    # Append to log file
    messages = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r') as f:
                messages = json.load(f)
        except (json.JSONDecodeError, IOError):
            messages = []

    messages.append(message)

    with open(LOG_FILE, 'w') as f:
        json.dump(messages, f, indent=2)


def clear_log():
    """Clear the log file. Called when starting a new session."""
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    # Create empty log file
    with open(LOG_FILE, 'w') as f:
        json.dump([], f)


def start_viewer():
    """
    Start the viewer as a separate process.
    This is called by server.py after connection is established.
    """
    # Clear previous log
    clear_log()

    # Start viewer in a new process
    viewer_script = os.path.abspath(__file__)
    subprocess.Popen([sys.executable, viewer_script, "--viewer"],
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)


def log_message(direction, sender, msg_type, encrypted_data, decrypted_content):
    """Convenience function to log a message (called by server.py)"""
    write_message_to_log(direction, sender, msg_type, encrypted_data, decrypted_content)


def stop_viewer():
    """Stop signal - write a stop marker to the log"""
    # Just add a stop marker - the viewer will detect it
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r') as f:
                messages = json.load(f)
            messages.append({"_stop": True})
            with open(LOG_FILE, 'w') as f:
                json.dump(messages, f, indent=2)
        except:
            pass


class EncryptionViewerGUI:
    """
    GUI window that monitors the log file and displays messages.
    Runs on the main thread as a standalone process.
    """

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Encryption Viewer - Chat Message Monitor")
        self.root.geometry("1000x700")
        self.root.configure(bg='#1e1e1e')

        self.messages = []
        self.last_count = 0
        self.selected_encrypted_data = None

        self._setup_gui()
        self._start_monitoring()

    def _setup_gui(self):
        """Set up the GUI components"""
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Treeview',
                        background='#2d2d2d',
                        foreground='#ffffff',
                        fieldbackground='#2d2d2d',
                        rowheight=30)
        style.configure('Treeview.Heading',
                        background='#404040',
                        foreground='#ffffff',
                        font=('Arial', 10, 'bold'))
        style.map('Treeview', background=[('selected', '#0078d4')])

        # Header
        header_frame = tk.Frame(self.root, bg='#0078d4', pady=10)
        header_frame.pack(fill=tk.X)

        title_label = tk.Label(
            header_frame,
            text="ENCRYPTION VIEWER - Live Message Monitor",
            font=('Arial', 16, 'bold'),
            fg='white',
            bg='#0078d4'
        )
        title_label.pack()

        subtitle_label = tk.Label(
            header_frame,
            text="Showing all messages with their encrypted and decrypted forms",
            font=('Arial', 10),
            fg='#e0e0e0',
            bg='#0078d4'
        )
        subtitle_label.pack()

        # Main content frame
        main_frame = tk.Frame(self.root, bg='#1e1e1e', padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Message list (treeview)
        list_frame = tk.Frame(main_frame, bg='#1e1e1e')
        list_frame.pack(fill=tk.BOTH, expand=True)

        columns = ('time', 'direction', 'sender', 'type', 'content')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=10)

        self.tree.heading('time', text='Time')
        self.tree.heading('direction', text='Direction')
        self.tree.heading('sender', text='Sender')
        self.tree.heading('type', text='Type')
        self.tree.heading('content', text='Decrypted Content')

        self.tree.column('time', width=80, minwidth=80)
        self.tree.column('direction', width=80, minwidth=80)
        self.tree.column('sender', width=100, minwidth=80)
        self.tree.column('type', width=60, minwidth=60)
        self.tree.column('content', width=400, minwidth=200)

        # Scrollbar for treeview
        tree_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind selection event
        self.tree.bind('<<TreeviewSelect>>', self._on_select)

        # Encrypted data display
        encrypted_frame = tk.LabelFrame(
            main_frame,
            text=" Encrypted Data (Click a message above to view) ",
            font=('Arial', 10, 'bold'),
            fg='#00ff00',
            bg='#1e1e1e',
            padx=10,
            pady=10
        )
        encrypted_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        self.encrypted_text = scrolledtext.ScrolledText(
            encrypted_frame,
            height=8,
            font=('Consolas', 9),
            bg='#0d0d0d',
            fg='#00ff00',
            insertbackground='#00ff00',
            wrap=tk.WORD
        )
        self.encrypted_text.pack(fill=tk.BOTH, expand=True)

        # Copy button
        button_frame = tk.Frame(encrypted_frame, bg='#1e1e1e')
        button_frame.pack(fill=tk.X, pady=(10, 0))

        copy_btn = tk.Button(
            button_frame,
            text="Copy Encrypted Data to Clipboard",
            font=('Arial', 10),
            bg='#404040',
            fg='white',
            activebackground='#505050',
            activeforeground='white',
            command=self._copy_to_clipboard
        )
        copy_btn.pack(side=tk.LEFT)

        # Info label
        info_label = tk.Label(
            button_frame,
            text="Use decrypt_message.py to decrypt this data",
            font=('Arial', 9, 'italic'),
            fg='#888888',
            bg='#1e1e1e'
        )
        info_label.pack(side=tk.LEFT, padx=(20, 0))

        # Status bar
        self.status_var = tk.StringVar(value="Waiting for messages...")
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            font=('Arial', 9),
            fg='#888888',
            bg='#2d2d2d',
            anchor=tk.W,
            padx=10,
            pady=5
        )
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def _start_monitoring(self):
        """Start monitoring the log file for new messages"""
        self._check_log_file()

    def _check_log_file(self):
        """Check log file for new messages"""
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'r') as f:
                    messages = json.load(f)

                # Check for stop signal
                for msg in messages:
                    if msg.get('_stop'):
                        self.status_var.set("Chat session ended")
                        return  # Stop monitoring

                # Add new messages
                if len(messages) > self.last_count:
                    for msg in messages[self.last_count:]:
                        if not msg.get('_stop'):
                            self._add_message(msg)
                    self.last_count = len(messages)

        except (json.JSONDecodeError, IOError):
            pass

        # Check again in 500ms
        self.root.after(500, self._check_log_file)

    def _add_message(self, message):
        """Add a message to the treeview"""
        self.messages.append(message)

        # Add to treeview
        direction_display = "-> SENT" if message['direction'] == 'SENT' else "<- RECV"
        content = message['decrypted_content']
        values = (
            message['timestamp'],
            direction_display,
            message['sender'],
            message['msg_type'],
            content[:100] + ('...' if len(content) > 100 else '')
        )

        item_id = self.tree.insert('', tk.END, values=values)

        # Auto-scroll to new item
        self.tree.see(item_id)

        # Update status
        self.status_var.set(f"Total messages: {len(self.messages)}")

    def _on_select(self, event):
        """Handle message selection"""
        selection = self.tree.selection()
        if not selection:
            return

        # Get index of selected item
        item = selection[0]
        index = self.tree.index(item)

        if index < len(self.messages):
            message = self.messages[index]
            self.selected_encrypted_data = message['encrypted_data']

            # Display encrypted data
            self.encrypted_text.delete('1.0', tk.END)
            self.encrypted_text.insert(tk.END, f"Sender: {message['sender']}\n")
            self.encrypted_text.insert(tk.END, f"Type: {message['msg_type']}\n")
            self.encrypted_text.insert(tk.END, f"Direction: {message['direction']}\n")
            self.encrypted_text.insert(tk.END, "-" * 70 + "\n")
            self.encrypted_text.insert(tk.END, "ENCRYPTED DATA (copy this to decrypt):\n")
            self.encrypted_text.insert(tk.END, message['encrypted_data'])
            self.encrypted_text.insert(tk.END, "\n" + "-" * 70 + "\n")
            self.encrypted_text.insert(tk.END, "DECRYPTED CONTENT:\n")
            self.encrypted_text.insert(tk.END, message['decrypted_content'])

    def _copy_to_clipboard(self):
        """Copy encrypted data to clipboard"""
        if self.selected_encrypted_data:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.selected_encrypted_data)
            self.status_var.set("Encrypted data copied to clipboard!")

    def run(self):
        """Run the GUI main loop"""
        self.root.mainloop()


def main_viewer():
    """Run the viewer GUI"""
    app = EncryptionViewerGUI()
    app.run()


if __name__ == "__main__":
    if "--viewer" in sys.argv:
        # Run as viewer process
        main_viewer()
    else:
        # Test mode - add some test messages and launch viewer
        print("Testing Encryption Viewer...")
        clear_log()

        # Start the viewer
        start_viewer()

        time.sleep(1)

        # Add some test messages
        test_encrypted = "gAAAAABh_test_encrypted_data_here_12345678901234567890abcdefghijklmnop"

        log_message("RECEIVED", "Alice", "TEXT", test_encrypted, "Hello, this is a test message!")
        time.sleep(0.5)
        log_message("SENT", "Bob", "TEXT", test_encrypted, "Hi Alice, nice to meet you!")
        time.sleep(0.5)
        log_message("RECEIVED", "Alice", "IMAGE", test_encrypted, "[IMAGE: photo.jpg (245.6 KB)]")

        print("Test messages added to log.")
        print("The viewer window should be open.")
        print("Press Ctrl+C to exit.")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            stop_viewer()
            print("\nDone.")
