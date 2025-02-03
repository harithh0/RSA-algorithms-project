import tkinter as tk

import operations
from generate_rsa import generate_rsa

public_key, private_key, n_value = generate_rsa()


def open_public_user_window():
    public_user_window = tk.Toplevel(main)
    public_user_window.title("Public User")
    public_user_window.geometry("400x300")
    public_user_window.config(bg="#E4E2E2")
    label = tk.Label(
        public_user_window,
        text="As a public user, what would you like to do?",
        bg="#E4E2E2",
        fg="#000",
    )
    label.pack(pady=20)
    s = tk.Button(
        master=public_user_window,
        text="1. Send an encrypted message",
        command=lambda: open_send_enc_message(public_user_window),
    )
    s.config(bg="#E4E2E2", fg="#000")
    s.pack(pady=10)

    button = tk.Button(
        master=public_user_window, text="2. Authenticate a digital signature"
    )
    button.config(bg="#E4E2E2", fg="#000")
    button.pack(pady=10)

    button1 = tk.Button(master=public_user_window, text="3. Exit", command=main.quit)
    button1.config(bg="#E4E2E2", fg="#000")
    button1.pack(pady=10)


def open_send_enc_message(parent_window):
    parent_window.destroy()
    send_enc_message_window = tk.Toplevel(main)
    send_enc_message_window.title("Send encrypted message")
    send_enc_message_window.geometry("400x300")
    send_enc_message_window.config(bg="#E4E2E2")
    label = tk.Label(
        send_enc_message_window,
        text="Enter your message to encrypt:",
        bg="#E4E2E2",
        fg="#000",
    )
    label.pack(pady=10)

    text_box = tk.Text(send_enc_message_window, height=10, width=40)
    text_box.pack(pady=10)

    def encrypt_and_display():
        message = text_box.get("1.0", tk.END)
        encrypted_message = operations.encrypt_message(message, public_key, n_value)

        # Create a new window to display the encrypted message
        encrypted_message_window = tk.Toplevel(send_enc_message_window)
        encrypted_message_window.title("Encrypted Message")
        encrypted_message_window.geometry("400x300")
        encrypted_message_window.config(bg="#E4E2E2")

        label = tk.Label(
            encrypted_message_window,
            text="Encrypted Message:",
            bg="#E4E2E2",
            fg="#000",
        )
        label.pack(pady=10)

        encrypted_text_box = tk.Text(encrypted_message_window, height=10, width=40)
        encrypted_text_box.pack(pady=10)
        encrypted_text_box.insert(tk.END, encrypted_message)
        encrypted_text_box.config(state=tk.DISABLED)  # Make the text box read-only

        def copy_to_clipboard():
            encrypted_message_window.clipboard_clear()
            encrypted_message_window.clipboard_append(encrypted_message)
            encrypted_message_window.update()  # Keeps the clipboard content after the window is closed

        copy_button = tk.Button(
            encrypted_message_window, text="Copy", command=copy_to_clipboard
        )
        copy_button.config(bg="#E4E2E2", fg="#000")
        copy_button.pack(pady=10)

    encrypt_button = tk.Button(
        send_enc_message_window, text="Encrypt!", command=encrypt_and_display
    )
    encrypt_button.config(bg="#E4E2E2", fg="#000")
    encrypt_button.pack(pady=10)


def open_decrypt_message(parent_window):
    parent_window.destroy()
    decrypt_message_window = tk.Toplevel(main)
    decrypt_message_window.title("Decrypt message")
    decrypt_message_window.geometry("400x300")
    decrypt_message_window.config(bg="#E4E2E2")
    label = tk.Label(
        decrypt_message_window,
        text="Enter the encrypted message to decrypt:",
        bg="#E4E2E2",
        fg="#000",
    )
    label.pack(pady=10)

    text_box = tk.Text(decrypt_message_window, height=10, width=40)
    text_box.pack(pady=10)

    def decrypt_and_display():
        encrypted_message = text_box.get("1.0", tk.END)
        decrypted_message = operations.decrypt_message(
            encrypted_message, private_key, n_value
        )

        # Create a new window to display the decrypted message
        decrypted_message_window = tk.Toplevel(decrypt_message_window)
        decrypted_message_window.title("Decrypted Message")
        decrypted_message_window.geometry("400x300")
        decrypted_message_window.config(bg="#E4E2E2")

        label = tk.Label(
            decrypted_message_window,
            text="Decrypted Message:",
            bg="#E4E2E2",
            fg="#000",
        )
        label.pack(pady=10)

        decrypted_text_box = tk.Text(decrypted_message_window, height=10, width=40)
        decrypted_text_box.pack(pady=10)
        decrypted_text_box.insert(tk.END, decrypted_message)
        decrypted_text_box.config(state=tk.DISABLED)  # Make the text box read-only

    decrypt_button = tk.Button(
        decrypt_message_window, text="Decrypt!", command=decrypt_and_display
    )
    decrypt_button.config(bg="#E4E2E2", fg="#000")
    decrypt_button.pack(pady=10)


def open_owner_window():
    owner_window = tk.Toplevel(main)
    owner_window.title("Owner")
    owner_window.geometry("500x400")
    owner_window.config(bg="#E4E2E2")
    label = tk.Label(
        owner_window,
        text="As the owner of the keys, what would you like to do?",
        bg="#E4E2E2",
        fg="#000",
    )
    label.pack(pady=20)
    decrypt_message_button = tk.Button(
        master=owner_window,
        text="1. Decrypt a received message",
        command=lambda: open_decrypt_message(owner_window),
    )
    decrypt_message_button.config(bg="#E4E2E2", fg="#000")
    decrypt_message_button.pack(pady=10)

    sign_button = tk.Button(master=owner_window, text="2. Digitally sign a message")
    sign_button.config(bg="#E4E2E2", fg="#000")
    sign_button.pack(pady=10)

    show_keys_button = tk.Button(master=owner_window, text="3. Show the keys")
    show_keys_button.config(bg="#E4E2E2", fg="#000")
    show_keys_button.pack(pady=10)

    generate_keys_button = tk.Button(
        master=owner_window, text="4. Generate a new set of the keys"
    )
    generate_keys_button.config(bg="#E4E2E2", fg="#000")
    generate_keys_button.pack(pady=10)

    exit_button = tk.Button(
        master=owner_window, text="5. Exit", command=owner_window.destroy
    )
    exit_button.config(bg="#E4E2E2", fg="#000")
    exit_button.pack(pady=10)


main = tk.Tk()
main.config(bg="#E4E2E2")
main.title("Main Window")

main.geometry("400x400")
main.resizable(False, False)

# Create a frame to hold the buttons and center them
frame = tk.Frame(main, bg="#E4E2E2")
frame.pack(expand=True)

header = tk.Label(
    master=frame, text="RSA keys have been generated.\nPlease select your user type: "
)
header.pack(pady=20)

s = tk.Button(master=frame, text="1. A public user", command=open_public_user_window)
s.config(bg="#E4E2E2", fg="#000")
s.pack(pady=10)

button = tk.Button(
    master=frame, text="2. The owner of the keys", command=open_owner_window
)
button.config(bg="#E4E2E2", fg="#000")
button.pack(pady=10)

button1 = tk.Button(master=frame, text="3. Exit", command=main.quit)
button1.config(bg="#E4E2E2", fg="#000")
button1.pack(pady=10)

main.mainloop()
