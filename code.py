import tkinter as tk
from tkinter import ttk, messagebox
import mysql.connector
import qrcode
import random
from io import BytesIO
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from captcha.image import ImageCaptcha
from PIL import Image, ImageTk
import os

# Constants (Replace with your own values)
SMTP_PORT = 587
SMTP_SERVER = "smtp.gmail.com"
EMAIL_FROM = "projectminor206@gmail.com"
PASSWORD = "zwmfjfwjvimmjddg"
SUBJECT = "New email from TIE with attachments!!"

# Database connection function
def connect_to_database():
    try:
        return mysql.connector.connect(
            host='localhost',
            port=3306,
            user='root',
            password='9005',
            database='mp'
        )
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None

def get_user_info(user_id, cursor):
    sql = "SELECT email, Username, pass FROM user WHERE Id = %s"
    cursor.execute(sql, (user_id,))
    result = cursor.fetchone()
    if result:
        email, username, pass_hash = result
        pass_decrypted = pass_hash  # No encryption/decryption
        return email, username, pass_decrypted
    else:
        return None

def generate_random_otp():
    return str(random.randint(100000, 999999))

def generate_qr_code(otp):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4
    )
    qr.add_data(otp)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return buffer

def send_email_with_qr(recipient, qr_buffer, otp):
    body = f"Your OTP for the verification:"
    msg = MIMEMultipart()
    msg['From'] = EMAIL_FROM
    msg['To'] = recipient
    msg['Subject'] = SUBJECT
    msg.attach(MIMEText(body, 'plain'))

    img_data = MIMEImage(qr_buffer.read(), name='otp_qr_code.png')
    qr_buffer.close()

    msg.attach(img_data)

    text = msg.as_string()

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as TIE_server:
            TIE_server.starttls()
            TIE_server.login(EMAIL_FROM, PASSWORD)
            print("Successfully connected to server")
            TIE_server.sendmail(EMAIL_FROM, recipient, text)
            print("Mail sent")
            return True
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def verify_username():
    global user_verified, username_entry, pin_entry, captcha_verified, generate_captcha_button
    user_id = int(pin_entry.get())
    username = username_entry.get()

    conn = connect_to_database()

    if conn:
        cursor = conn.cursor()
        user_info = get_user_info(user_id, cursor)

        if user_info:
            email, db_username, pass_hash = user_info
            pass_decrypted = pass_hash  # No encryption/decryption

            if username == db_username:
                messagebox.showinfo("Username Verification", "Username Verified")
                user_verified = True
                generate_captcha_button.config(state='normal')
            else:
                messagebox.showinfo("Username Verification", "Username not found in database!")
        else:
            messagebox.showinfo("Username Verification", "Record not found")

        conn.close()


def generate_captcha():
    global captcha_verified, captcha_label, verify_captcha_button, generate_otp_button
    if not user_verified:
        messagebox.showinfo("CAPTCHA Generation", "Please verify username first")
        return

    capt = ImageCaptcha()
    text = str(random.randint(1000, 9999))
    capt.generate(text)

    captcha_image = ImageTk.PhotoImage(capt.generate_image(text))
    captcha_label.config(image=captcha_image)
    captcha_label.image = captcha_image
    captcha_verified = text
    verify_captcha_button.config(state='normal')

def verify_captcha():
    global captcha_verified, captcha_entry, info_label, generate_otp_button
    user_captcha = captcha_entry.get()

    if user_captcha == captcha_verified:
        info_label.config(text="CAPTCHA Verified")
        captcha_verified = True
        generate_otp_button.config(state='normal')
    else:
        info_label.config(text="Wrong CAPTCHA")

def generate_otp():
    global otp, passwd, pin_entry, username_entry, generate_captcha_button, verify_captcha_button, password_entry, authenticate_button, info_label
    if not captcha_verified:
        info_label.config(text="Please verify CAPTCHA first")
        return

    user_id = int(pin_entry.get())
    conn = connect_to_database()

    if conn:
        cursor = conn.cursor()
        user_info = get_user_info(user_id, cursor)

        if user_info:
            email, db_username, passwd = user_info

            if username_entry.get() == db_username:
                info_label.config(text="Username is Verified")

                otp = generate_random_otp()
                otp_qr_buffer = generate_qr_code(otp)

                email_sent = send_email_with_qr(email, otp_qr_buffer, otp)
                if email_sent:
                    info_label.config(text="OTP sent to your email")
                else:
                    info_label.config(text="Failed to send OTP email. Please try again.")

                verify_otp_button.config(state='normal')

                verify_otp_button.config(state='normal')
                generate_captcha_button.config(state='disabled')
                verify_captcha_button.config(state='disabled')
                password_entry.config(state='disabled')
                authenticate_button.config(state='disabled')

                password_entry.delete(0, 'end')
            else:
                info_label.config(text="Username is not in database!")
        else:
            info_label.config(text="Record not found")

        conn.close()

def verify_otp():
    global otp_verified, otp_entry, otp, info_label, password_entry, authenticate_button
    otp_from_user = otp_entry.get()

    if otp_from_user == otp:
        info_label.config(text="OTP is Valid")
        otp_verified = True
        password_entry.config(state='normal')
        authenticate_button.config(state='normal')
    else:
        info_label.config(text="OTP is not Valid")

def authenticate_user():
    global otp_verified, passwd, otp_entry, password_entry, info_label, otp
    otp_from_user = otp_entry.get()
    p = password_entry.get()

    if otp_verified:
        if p == passwd:
            info_label.config(text="Password verified\nYou are authentic")
            show_success_window()
        else:
            info_label.config(text="Wrong password")
    else:
        info_label.config(text="Please verify OTP first")

def show_success_window():
    success_window = tk.Toplevel(root)
    success_window.title("Authentication Successful")

    label = ttk.Label(success_window, text="You are an authentic user!", font=("Helvetica", 16))
    label.pack(padx=20, pady=20)

    close_button = ttk.Button(success_window, text="Close", command=success_window.destroy)
    close_button.pack(pady=10)

def main():
    global root, pin_entry, username_entry, captcha_entry, captcha_label, otp_entry, password_entry, info_label
    global generate_captcha_button, verify_username_button, verify_captcha_button, generate_otp_button, verify_otp_button, authenticate_button
    root = tk.Tk()
    root.title("Authentication GUI")
    root.configure(bg="#FF9933")

    background_image = Image.open(r"C:\Users\HP\OneDrive\Pictures\wallpaperflare.com_wallpaper (6).jpg")
    background_image = background_image.resize((root.winfo_screenwidth(), root.winfo_screenheight()), Image.ANTIALIAS)
    background_photo = ImageTk.PhotoImage(background_image)

    background_label = ttk.Label(root, image=background_photo)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    style = ttk.Style()

    style.configure('WhiteLabel.TLabel', font=('Arial', 14), foreground='#FFFFFF', background='#FF9933')
    style.configure('BlackYellow.TEntry', font=('Arial', 12), foreground='#000000', fieldbackground='#FFFF00')
    style.configure('Red.TButton', font=('Arial', 12, 'bold'), foreground='#FF0000', background='#FF0000')

    pin_label = ttk.Label(root, text="Enter the pin:", style='RedLabel.TLabel')
    pin_entry = ttk.Entry(root, style='BlackYellow.TEntry')

    username_label = ttk.Label(root, text="Enter the user name:", style='RedLabel.TLabel')
    username_entry = ttk.Entry(root, style='BlackYellow.TEntry')

    verify_username_button = ttk.Button(root, text="Verify Username", command=verify_username, style='Red.TButton')

    generate_captcha_button = ttk.Button(root, text="Generate CAPTCHA", command=generate_captcha, style='Red.TButton')
    generate_captcha_button.state(['disabled'])

    captcha_label = ttk.Label(root)
    captcha_entry = ttk.Entry(root, style='BlackYellow.TEntry')
    verify_captcha_button = ttk.Button(root, text="Verify CAPTCHA", command=verify_captcha, style='Red.TButton')
    verify_captcha_button.state(['disabled'])

    otp_label = ttk.Label(root, text="Enter the OTP you received on mail:", style='RedLabel.TLabel')
    otp_entry = ttk.Entry(root, style='BlackYellow.TEntry')

    generate_otp_button = ttk.Button(root, text="Generate OTP", command=generate_otp, style='Red.TButton')
    generate_otp_button.state(['disabled'])

    verify_otp_button = ttk.Button(root, text="Verify OTP", command=verify_otp, style='Red.TButton')
    verify_otp_button.state(['disabled'])

    password_label = ttk.Label(root, text="Enter your password:", style='RedLabel.TLabel')
    password_entry = ttk.Entry(root, show="*", style='BlackYellow.TEntry')
    password_entry.state(['disabled'])

    authenticate_button = ttk.Button(root, text="Authenticate", command=authenticate_user, style='Red.TButton')
    authenticate_button.state(['disabled'])

    info_label = ttk.Label(root, text="", font=('Arial', 12), background="#FF9933")

    pin_label.pack(pady=(20, 5))
    pin_entry.pack(pady=(0, 10))

    username_label.pack(pady=(0, 5))
    username_entry.pack(pady=(0, 10))

    verify_username_button.pack(pady=(0, 10))
    generate_captcha_button.pack(pady=(0, 5))

    captcha_label.pack()
    captcha_entry.pack(pady=(0, 10))
    verify_captcha_button.pack(pady=(0, 10))

    otp_label.pack(pady=(0, 5))
    otp_entry.pack(pady=(0, 10))

    generate_otp_button.pack(pady=(0, 5))
    verify_otp_button.pack(pady=(0, 10))

    password_label.pack(pady=(0, 5))
    password_entry.pack(pady=(0, 10))

    authenticate_button.pack(pady=(0, 10))
    info_label.pack()

    root.mainloop()

if __name__ == "__main__":
    main()
