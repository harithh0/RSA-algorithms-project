import json
import tkinter as tk
from tkinter import messagebox

import operations
from generate_rsa import generate_rsa

public_key, private_key, n_value = generate_rsa()

encrypted_messages_list = []
signed_messages_list = []


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
        master=public_user_window,
        text="2. Authenticate a digital signature",
        command=lambda: open_authenticate_digital_signature(public_user_window),
    )
    button.config(bg="#E4E2E2", fg="#000")
    button.pack(pady=10)

    button1 = tk.Button(
        master=public_user_window, text="3. exit", command=public_user_window.destroy
    )
    button1.config(bg="#e4e2e2", fg="#000")
    button1.pack(pady=10)


def open_authenticate_digital_signature(parent_window):
    parent_window.destroy()
    auth_message_window = tk.Toplevel(main)
    auth_message_window.title("Decrypt message")
    auth_message_window.geometry("500x400")
    auth_message_window.config(bg="#E4E2E2")
    label = tk.Label(
        auth_message_window,
        text="The following messages are available:",
        bg="#E4E2E2",
        fg="#000",
    )
    label.pack(pady=10)

    entry_label = tk.Label(
        auth_message_window,
        text="Enter message number:",
        bg="#E4E2E2",
        fg="#000",
    )

    text_box = tk.Text(auth_message_window, height=10, width=40)
    text_box.pack(pady=10)

    entry_label.pack(pady=5)
    if len(signed_messages_list) == 0:
        text_box.insert(tk.END, "No messages available")
    # Insert all encrypted messages into the text box
    index = 0
    for message in signed_messages_list:
        message_json = json.loads(message)
        message_content = message_json["message"]
        messag_signature = message_json["signature"]
        text_box.insert(tk.END, f"{index + 1}. {message_content}\n")
        index += 1

    text_box.config(state=tk.DISABLED)  # Make the text box read-only

    def get_message_values_from_list(index_number):
        message = signed_messages_list[index_number - 1]
        message_json = json.loads(message)
        message_content = message_json["message"]
        message_signature = message_json["signature"]
        return message_content, message_signature

    def verify_and_display():
        index_chosen = int(index_selected_box.get())
        content, signature = get_message_values_from_list(index_chosen)
        is_message_valid = operations.verify_message(
            content, int(signature), public_key, n_value
        )

        if is_message_valid == True:
            messagebox.showinfo(
                "Message Verification Passed",
                "Signature is valid.",
            )
        elif is_message_valid == False:
            messagebox.showerror(
                "Message Verification Failed",
                "The message signature does not match correctly",
            )

        # Create a new window to display the decrypted message
        # verify_message_window = tk.Toplevel(decrypt_message_window)
        # verify_message_window.title("Decrypted Message")
        # verify_message_window.geometry("400x300")
        # verify_message_window.config(bg="#E4E2E2")

        # label = tk.Label(
        #     decrypted_message_window,
        #     text="Decrypted Message:",
        #     bg="#E4E2E2",
        #     fg="#000",
        # )
        # label.pack(pady=10)

        # decrypted_text_box = tk.Text(decrypted_message_window, height=10, width=40)
        # decrypted_text_box.pack(pady=10)
        # decrypted_text_box.insert(tk.END, decrypted_message)
        # decrypted_text_box.config(state=tk.DISABLED)  # Make the text box read-only

    verify_button = tk.Button(
        auth_message_window, text="Verify!", command=verify_and_display
    )

    index_selected_box = tk.Entry(auth_message_window, width=10)
    index_selected_box.pack(padx=5)

    verify_button.config(bg="#E4E2E2", fg="#000")
    verify_button.pack(padx=10)


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

    # Old version
    # def encrypt_and_display():
    #     message = text_box.get("1.0", tk.END)
    #     encrypted_message = operations.encrypt_message(message, public_key, n_value)

    #     # Create a new window to display the encrypted message
    #     encrypted_message_window = tk.Toplevel(send_enc_message_window)
    #     encrypted_message_window.title("Encrypted Message")
    #     encrypted_message_window.geometry("400x300")
    #     encrypted_message_window.config(bg="#E4E2E2")

    #     label = tk.Label(
    #         encrypted_message_window,
    #         text="Encrypted Message:",
    #         bg="#E4E2E2",
    #         fg="#000",
    #     )
    #     label.pack(pady=10)

    #     encrypted_text_box = tk.Text(encrypted_message_window, height=10, width=40)
    #     encrypted_text_box.pack(pady=10)
    #     encrypted_text_box.insert(tk.END, encrypted_message)
    #     encrypted_text_box.config(state=tk.DISABLED)  # Make the text box read-only

    #     def copy_to_clipboard():
    #         encrypted_message_window.clipboard_clear()
    #         encrypted_message_window.clipboard_append(encrypted_message)
    #         encrypted_message_window.update()  # Keeps the clipboard content after the window is closed

    #     copy_button = tk.Button(
    #         encrypted_message_window, text="Copy", command=copy_to_clipboard
    #     )
    #     copy_button.config(bg="#E4E2E2", fg="#000")
    #     copy_button.pack(pady=10)

    # encrypt_button = tk.Button(
    #     send_enc_message_window, text="Encrypt!", command=encrypt_and_display
    # )

    def encrypt_and_send():
        message = text_box.get("1.0", tk.END)
        message = message.strip()
        encrypted_message = operations.encrypt_message(message, public_key, n_value)
        encrypted_messages_list.append(
            f'{{"length" : {len(message)}, "encrypted_message" : "{encrypted_message}"}}'
        )
        messagebox.showinfo(
            "Operation successful", "Message has been successfully encrypted and sent!"
        )

    # encrypt_button = tk.Button(
    #     send_enc_message_window, text="Encrypt!", command=encrypt_and_display
    # )

    encrypt_button = tk.Button(
        send_enc_message_window, text="Encrypt and send!", command=encrypt_and_send
    )
    encrypt_button.config(bg="#E4E2E2", fg="#000")
    encrypt_button.pack(pady=10)


def open_decrypt_message(parent_window):
    parent_window.destroy()
    decrypt_message_window = tk.Toplevel(main)
    decrypt_message_window.title("Decrypt message")
    decrypt_message_window.geometry("500x400")
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

    if len(encrypted_messages_list) == 0:
        text_box.insert(tk.END, "No encrypted messages available")
    # Insert all encrypted messages into the text box
    index = 0
    for message in encrypted_messages_list:
        message_json = json.loads(message)
        message_len = message_json["length"]
        text_box.insert(tk.END, f"{index + 1}. (length = {message_len})\n")
        index += 1

    text_box.config(state=tk.DISABLED)  # Make the text box read-only

    def get_encrypted_message_from_list(index_number):
        message = encrypted_messages_list[index_number - 1]
        message_json = json.loads(message)
        encrypted_content = message_json["encrypted_message"]
        return encrypted_content

    def decrypt_and_display():
        encrypted_message = get_encrypted_message_from_list(
            int(index_selected_box.get())
        )
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

    entry_label = tk.Label(
        decrypt_message_window,
        text="Enter message number:",
        bg="#E4E2E2",
        fg="#000",
    )

    entry_label.pack(pady=5)
    index_selected_box = tk.Entry(decrypt_message_window, width=10)
    index_selected_box.pack(padx=5)


    decrypt_button = tk.Button(
        decrypt_message_window, text="Decrypt!", command=decrypt_and_display
    )
    decrypt_button.config(bg="#E4E2E2", fg="#000")
    decrypt_button.pack(padx=10)


def open_sign_message(parent_window):
    parent_window.destroy()
    sign_message_window = tk.Toplevel(main)
    sign_message_window.title("Sign Message")
    sign_message_window.geometry("400x300")
    sign_message_window.config(bg="#E4E2E2")
    label = tk.Label(
        sign_message_window,
        text="Enter your message to sign:",
        bg="#E4E2E2",
        fg="#000",
    )
    label.pack(pady=10)

    text_box = tk.Text(sign_message_window, height=10, width=40)
    text_box.pack(pady=10)

    def sign_and_send():
        message = text_box.get("1.0", tk.END)
        message = message.strip()
        message_signature = operations.sign_message(message, private_key, n_value)
        signed_messages_list.append(
            f'{{"message" : "{message}", "signature" : "{message_signature}"}}'
        )
        messagebox.showinfo(
            "Operation successful", "Message has been successfully signed and sent!"
        )

    sign_button = tk.Button(
        sign_message_window, text="Sign and send!", command=sign_and_send
    )
    sign_button.config(bg="#E4E2E2", fg="#000")
    sign_button.pack(padx=10)


def open_show_keys(parent_window):
    parent_window.destroy()
    show_keys_window = tk.Toplevel(main)
    show_keys_window.title("Keys")
    show_keys_window.geometry("400x300")
    show_keys_window.config(bg="#E5E2E2")
    label = tk.Label(
        show_keys_window,
        text="Current Keys:",
        bg="#E4E2E2",
        fg="#000",
    )
    label.pack(pady=10)

    text_box = tk.Text(show_keys_window, height=15, width=60)
    text_box.pack(pady=10)
    text_box.insert(tk.END, f"Public Key: {public_key}\nPrivate key: {private_key}")


def generate_new_keys():
    # generates and updates the new rsa values
    # need global to be able to change the values, without global it will create local varibles instead. If you are accessing it or adding/subtracting to it you dont need global. You need global when reassigning the object or deleting it.
    global public_key, private_key, n_value, encrypted_messages_list, signed_messages_list
    new_public_key, new_private_key, new_n_value = generate_rsa()
    public_key = new_public_key
    private_key = new_private_key
    n_value = new_n_value

    # deletes the old encrypted and signed messages, as can encrypt/decrypt/sign with the new keys
    del encrypted_messages_list, signed_messages_list
    messagebox.showinfo("Operation successful", "New RSA keys generated")


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

    sign_button = tk.Button(
        master=owner_window,
        text="2. Digitally sign a message",
        command=lambda: open_sign_message(owner_window),
    )
    sign_button.config(bg="#E4E2E2", fg="#000")
    sign_button.pack(pady=10)

    show_keys_button = tk.Button(
        master=owner_window,
        text="3. Show the keys",
        command=lambda: open_show_keys(owner_window),
    )
    show_keys_button.config(bg="#E4E2E2", fg="#000")
    show_keys_button.pack(pady=10)

    generate_keys_button = tk.Button(
        master=owner_window,
        text="4. Generate a new set of the keys",
        command=generate_new_keys,
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

button1 = tk.Button(
    master=frame,
    text="3. Exit",
    command=lambda: (messagebox.showinfo("Exiting...", "Bye for now!"), main.quit()),
)
button1.config(bg="#E4E2E2", fg="#000")
button1.pack(pady=10)

main.mainloop()
