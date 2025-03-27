import os
import re
import json
from tkinter import Tk, Label, Button, Entry, filedialog, messagebox, Toplevel, StringVar, OptionMenu, Listbox, Scrollbar, Text, PhotoImage
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import base64
import hashlib

from inspect import getsourcefile
from os.path import abspath

# Файл для хранения пароля и кодового слова
CREDENTIALS_FILE = 'credentials.json'
# Файл для хранения истории операций
HISTORY_FILE = 'history.txt'

# Журнал операций
history = []

# Генерация ключа шифрования на основе пароля
def generate_key(password, salt, algorithm='AES'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    if algorithm == 'AES':
        key = base64.urlsafe_b64encode(key)
    return key

# Проверка сложности пароля
def is_valid_password(password):
    if (len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'\d', password) and
        re.search(r'[!?&.,_=\-#%№\\/]', password)):
        return True
    return False

# Шифрование файла
def encrypt_file(file_path, password, algorithm='AES'):
    salt = os.urandom(16)
    key = generate_key(password, salt, algorithm)

    with open(file_path, "rb") as file:
        original = file.read()

    if algorithm == 'AES':
        fernet = Fernet(key)
        encrypted = fernet.encrypt(original)
    elif algorithm == 'ChaCha20':
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        encrypted = nonce + chacha.encrypt(nonce, original, None)

    with open(file_path + ".encrypted", "wb") as encrypted_file:
        encrypted_file.write(salt + encrypted)

    os.remove(file_path)
    messagebox.showinfo("Успех", f"Файл '{file_path}' зашифрован.")
    history.append(f"Зашифрован файл: {file_path}")
    save_history()

# Дешифрование файла
def decrypt_file(file_path, password, algorithm='AES'):
    try:
        with open(file_path, "rb") as encrypted_file:
            salt = encrypted_file.read(16)
            encrypted = encrypted_file.read()

        key = generate_key(password, salt, algorithm)

        if algorithm == 'AES':
            fernet = Fernet(key)
            decrypted = fernet.decrypt(encrypted)
        elif algorithm == 'ChaCha20':
            nonce = encrypted[:12]
            chacha = ChaCha20Poly1305(key)
            decrypted = chacha.decrypt(nonce, encrypted[12:], None)
        return decrypted
    except Exception as e:
        messagebox.showerror("Ошибка", f"Неверный пароль или поврежденный файл: {e}")
        return None

# Проверка целостности файла
def check_integrity(original_path, decrypted_data):
    original_hash = hashlib.sha256()
    decrypted_hash = hashlib.sha256()

    with open(original_path, "rb") as original_file:
        while chunk := original_file.read(8192):
            original_hash.update(chunk)

    decrypted_hash.update(decrypted_data)

    if original_hash.digest() == decrypted_hash.digest():
        messagebox.showinfo("Целостность", "Целостность файла подтверждена.")
    else:
        messagebox.showerror("Целостность", "Целостность файла нарушена.")

# Сохранение истории в файл
def save_history():
    with open(HISTORY_FILE, 'w') as f:
        for item in history:
            f.write(f"{item}\n")

# Загрузка истории из файла
def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            return f.read().splitlines()
    return []

# Открытие файла для шифрования
def open_file_encrypt():
    file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
    if file_path:
        password = password_entry_main.get()
        algorithm = encryption_algorithm.get()
        if password:
            encrypt_file(file_path, password, algorithm)
        else:
            messagebox.showwarning("Предупреждение", "Введите пароль для шифрования.")

# Открытие файла для дешифрования
def open_file_decrypt():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.encrypted")])
    if file_path:
        password = password_entry_main.get()
        algorithm = encryption_algorithm.get()
        if password:
            decrypted_data = decrypt_file(file_path, password, algorithm)
            if decrypted_data:
                output_file_path = file_path.replace(".encrypted", "")
                with open(output_file_path, "wb") as decrypted_file:
                    decrypted_file.write(decrypted_data)
                messagebox.showinfo("Успех", f"Файл '{file_path}' расшифрован.")
                history.append(f"Расшифрован файл: {file_path}")
                save_history()
        else:
            messagebox.showwarning("Предупреждение", "Введите пароль для дешифрования.")

# Показ истории операций
def show_history():
    history_window = Toplevel(main_win)
    history_window.geometry("839x843")
    history_window.title("История операций")
    listbox = Listbox(history_window, font=("Arial", 12))
    scrollbar = Scrollbar(history_window, orient="vertical", command=listbox.yview)
    listbox.config(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    listbox.pack(expand=1, fill='both')

    for item in history:
        listbox.insert("end", item)

# Сохранение пароля и кодового слова
def save_credentials(password, codeword):
    credentials = {
        "password": password,
        "codeword": codeword
    }
    with open(CREDENTIALS_FILE, 'w') as f:
        json.dump(credentials, f)

# Загрузка пароля и кодового слова
def load_credentials():
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'r') as f:
            return json.load(f)
    return None

# Показ информации о пароле и кодовом слове
def show_password_info():
    messagebox.showinfo("Информация о пароле и кодовом слове",
                        "Пароль должен состоять не менее чем из 8 символов, "
                        "иметь минимум одну заглавную букву, "
                        "одну цифру и разрешенные символы: !?&.,_=-#%№\\/.\n\n"
                        "Кодовое слово будет использоваться для смены пароля.")

# Создание пароля при первом запуске
def create_password():
    def save_password():
        password = password_entry.get()
        confirm_password = confirm_password_entry.get()
        codeword = codeword_entry.get()
        if password == confirm_password:
            if is_valid_password(password):
                save_credentials(password, codeword)
                create_password_window.destroy()
                main_window()
            else:
                messagebox.showwarning("Предупреждение", "Пароль не соответствует требованиям.")
        else:
            messagebox.showwarning("Предупреждение", "Пароли не совпадают.")

    create_password_window = Toplevel(app)
    create_password_window.geometry("839x843")
    create_password_window.title("Создание пароля")
    
    create_password_window.resizable(width=False, height=False)  # Запрет изменения размеров окна    
    background_label = Label(create_password_window, image=background_image)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)
    

    Label(create_password_window, text="Создайте пароль:", font=("Helvetica", 18), bg="#7FDBFF").pack(pady=10)
    password_entry = Entry(create_password_window, show="*", font=("Helvetica", 18))
    password_entry.pack(pady=5)
    Label(create_password_window, text="Подтвердите пароль:", font=("Helvetica", 18), bg="#7FDBFF").pack(pady=10)
    confirm_password_entry = Entry(create_password_window, show="*", font=("Helvetica", 18))
    confirm_password_entry.pack(pady=5)
    Label(create_password_window, text="Введите кодовое слово:", font=("Helvetica", 18), bg="#7FDBFF").pack(pady=10)
    codeword_entry = Entry(create_password_window, font=("Helvetica", 18))
    codeword_entry.pack(pady=5)
    Label(create_password_window, text="Требования к паролю:\n- Минимум 8 символов\n- Минимум одна заглавная буква\n- Минимум одна цифра\n- Разрешенные символы: !?&.,_=-#%№\\/", font=("Helvetica", 14), bg="#7FDBFF").pack(pady=10)
    Button(create_password_window, text="Сохранить", command=save_password, bg="#DDDDDD", font=("Helvetica", 18, "bold")).pack(pady=20)
    Button(create_password_window, text="?", command=show_password_info, bg="#DDDDDD", font=("Helvetica", 18, "bold")).pack(pady=10)
    
    
    

# Смена пароля
def change_password():
    def save_new_password():
        current_codeword = current_codeword_entry.get()
        new_password = new_password_entry.get()
        confirm_new_password = confirm_new_password_entry.get()
        credentials = load_credentials()
        if credentials and current_codeword == credentials["codeword"]:
            if new_password == confirm_new_password:
                if is_valid_password(new_password):
                    save_credentials(new_password, current_codeword)
                    change_password_window.destroy()
                    messagebox.showinfo("Успех", "Пароль успешно изменен.")
                else:
                    messagebox.showwarning("Предупреждение", "Пароль не соответствует требованиям.")
            else:
                messagebox.showwarning("Предупреждение", "Пароли не совпадают.")
        else:
            messagebox.showwarning("Ошибка", "Неверное кодовое слово.")

    change_password_window = Toplevel(app)
    change_password_window.geometry("839x843")
    change_password_window.title("Смена пароля")
    # change_password_window.configure(bg='#7FDBFF')  # Фон цвета первого скриншота
    
    change_password_window.resizable(width=False, height=False)  # Запрет изменения размеров окна    
    background_label = Label(change_password_window, image=background_image)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    Label(change_password_window, text="Введите кодовое слово:", font=("Helvetica", 18), bg="#7FDBFF").pack(pady=10)
    current_codeword_entry = Entry(change_password_window, font=("Helvetica", 18))
    current_codeword_entry.pack(pady=5)
    Label(change_password_window, text="Введите новый пароль:", font=("Helvetica", 18), bg="#7FDBFF").pack(pady=10)
    new_password_entry = Entry(change_password_window, show="*", font=("Helvetica", 18))
    new_password_entry.pack(pady=5)
    Label(change_password_window, text="Подтвердите новый пароль:", font=("Helvetica", 18), bg="#7FDBFF").pack(pady=10)
    confirm_new_password_entry = Entry(change_password_window, show="*", font=("Helvetica", 18))
    confirm_new_password_entry.pack(pady=5)
    Button(change_password_window, text="Сохранить", command=save_new_password, bg="#DDDDDD", font=("Helvetica", 18, "bold")).pack(pady=20)

# Функция для входа в приложение с паролем
def login():
    entered_password = password_entry.get()
    credentials = load_credentials()
    if credentials and entered_password == credentials["password"]:
        app.destroy()  # Закрываем окно входа
        main_window()
    else:
        messagebox.showerror("Ошибка", "Неверный пароль")

# Главное окно приложения
def main_window():
    global main_win
    global password_entry_main
    global encryption_algorithm
    
    

    # Создание основного окна
    main_win = Tk()
    
 
    main_win.title("Drago Shield")
    main_win.geometry("839x843")
    main_win.configure(bg='#7FDBFF')  # Фон цвета первого скриншота
    main_win.resizable(width=False, height=False)  # Запрет изменения размеров окна
    
   
    background_image = PhotoImage(file=os.path.dirname(abspath(getsourcefile(lambda:0))) + "/background.png")
    
    background_label = Label(main_win, image=background_image)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    
    

    # Заголовок
    header = Label(main_win, text="Drago Shield", font=("Helvetica", 24, "bold"), fg="blue", bg='#7FDBFF')
    header.place(relx=0.5, rely=0.1, anchor="center")

    # Ввод пароля
    password_label = Label(main_win, text="Введите пароль:", font=("Helvetica", 16), fg="blue", bg='#7FDBFF')
    password_label.place(relx=0.05, rely=0.25, anchor="w")
    password_entry_main = Entry(main_win, show="*", font=("Helvetica", 16))
    password_entry_main.place(relx=0.05, rely=0.3, anchor="w")

    # Выбор алгоритма шифрования
    algorithm_label = Label(main_win, text="Выберите алгоритм:", font=("Helvetica", 16), fg="blue", bg='#7FDBFF')
    algorithm_label.place(relx=0.95, rely=0.4, anchor="e")
    algorithm_options = ["AES", "ChaCha20"]
    encryption_algorithm = StringVar(main_win)
    encryption_algorithm.set(algorithm_options[0])  # Устанавливаем алгоритм по умолчанию
    option_menu = OptionMenu(main_win, encryption_algorithm, *algorithm_options)
    option_menu.config(font=("Helvetica", 14))
    option_menu.place(relx=0.95, rely=0.45, anchor="e")

    # Кнопки
    encrypt_button = Button(main_win, text="Зашифровать файл", command=open_file_encrypt, bg="#DDDDDD", font=("Sans", 16, "bold"), fg="blue")
    encrypt_button.place(relx=0.05, rely=0.5, anchor="w")

    decrypt_button = Button(main_win, text="Расшифровать файл", command=open_file_decrypt, bg="#DDDDDD", font=("Sans", 16, "bold"), fg="blue")
    decrypt_button.place(relx=0.05, rely=0.6, anchor="w")

    history_button = Button(main_win, text="История операций", command=show_history, bg="#DDDDDD", font=("Sans", 16, "bold"), fg="blue")
    history_button.place(relx=0.05, rely=0.7, anchor="w")

    change_password_button = Button(main_win, text="Сменить пароль", command=change_password, bg="#DDDDDD", font=("Sans", 16, "bold"), fg="blue")
    change_password_button.place(relx=0.05, rely=0.8, anchor="w")

    # Кнопка с пояснением
    info_button = Button(main_win, text="?", command=show_info_popup, bg="#DDDDDD", font=("Sans", 16, "bold"), fg="blue")
    info_button.place(relx=0.95, rely=0.95, anchor="se")
    
   

    main_win.mainloop()

# Функция для показа всплывающего окна с информацией о разнице между AES и ChaCha20
def show_info_popup():
    info_window = Toplevel(main_win)
    info_window.geometry("839x843")
    info_window.title("Разница между AES и ChaCha20")
    info_text = ("AES (Advanced Encryption Standard) - это способ защиты вашей информации.\n"
                 "ChaCha20 - также симметричный ключевой алгоритм шифрования вашей информации.\n"
                 "Если ваш ПК слабый, рекомендуется использовать ChaCha20.")
    info_label = Label(info_window, text=info_text, font=("Arial", 14), justify="left")
    info_label.pack(padx=10, pady=10)

# Создание начального окна для входа или создания пароля
def show_initial_window():
    global app, password_entry, background_image
    
    

    app = Tk()
    app.title("Вход в приложение")
    app.geometry("839x843")
    # app.configure(bg='#7FDBFF')  # Фон цвета первого скриншота
    app.resizable(width=False, height=False)  # Запрет изменения размеров окна
    
    
    background_image = PhotoImage(file=os.path.dirname(abspath(getsourcefile(lambda:0))) + "/background.png")
    background_label = Label(app, image=background_image)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)
    
    

    credentials = load_credentials()
    if credentials:
        # Ввод пароля для входа
        Label(app, text="Введите пароль для входа:", font=("Helvetica", 18), bg="#7FDBFF").pack(pady=10)
        password_entry = Entry(app, show="*", font=("Helvetica", 18))
        password_entry.pack(pady=10)
        # Кнопка для входа
        login_button = Button(app, text="Войти", command=login, bg="#DDDDDD", font=("Helvetica", 18, "bold"))
        login_button.pack(pady=10)
        # Кнопка для смены пароля
        change_password_button = Button(app, text="Смена пароля", command=change_password, bg="#DDDDDD", font=("Helvetica", 18, "bold"))
        change_password_button.pack(pady=10)
    else:
        create_password()

    app.mainloop()

# Загрузка истории при старте
history = load_history()

# Запуск начального окна
show_initial_window()
