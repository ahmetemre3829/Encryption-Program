from nacl.secret import SecretBox
from nacl.utils import random
import os
import tkinter as tk
from tkinter import filedialog
import time
import colorama
from colorama import Fore, Style
import hashlib
from argon2.low_level import hash_secret_raw, Type
import msvcrt
import asyncio
from aiogram import Bot, types
from aiogram.utils.exceptions import TelegramAPIError
import aiohttp
import platform
import sqlite3



colorama.init(autoreset=True)

DEFAULT_CHUNK_SIZE2 = 1 * 1024* 1024 #1MB
CHUNK_SIZE2 = DEFAULT_CHUNK_SIZE2
DEFAULT_CHUNK_SIZE = 2 * 1024 * 1024  # 2 MB
CHUNK_SIZE = DEFAULT_CHUNK_SIZE

def dosya_sec():
    root = tk.Tk()
    root.withdraw()
    dosya_yolu = filedialog.askopenfilename(title="Select the file you want to encrypt")
    return dosya_yolu

def dosya_sec1():
    root = tk.Tk()
    root.withdraw()
    dosya_yolu = filedialog.askopenfilename(title="Select the file you want to decrypt")
    return dosya_yolu

def dosya_sec2():
    root = tk.Tk()
    root.withdraw()
    dosya_yolu = filedialog.askopenfilename(title="Select file to calculate SHA-256 hash value")
    return dosya_yolu

def dosya_sec3():
    root = tk.Tk()
    root.withdraw()
    dosya_yolu = filedialog.askopenfilename(title="Select the file you want to send to the producer")
    return dosya_yolu

def calculate_hash(file_name):
    hash_func = hashlib.sha256()
    with open(file_name, 'rb') as f:
        total_size = os.path.getsize(file_name)
        hashed_size = 0
        start_time = time.time()
        while chunk:= f.read(CHUNK_SIZE2):
            hash_func.update(chunk)
            hashed_size += len(chunk)
            print_progress(hashed_size, total_size, start_time)
    return hash_func.hexdigest()

def calculate_hash2(file_name):
    hash_func = hashlib.sha256()
    with open(file_name, 'rb') as f:
        while chunk:= f.read(CHUNK_SIZE2):
          hash_func.update(chunk)
    return hash_func.hexdigest()


def encrypt_file(file_name, key):
    box = SecretBox(key)
    
    total_size = os.path.getsize(file_name)
    encrypted_size = 0

    # Dosya adından uzantıyı ayır
    file_base_name, file_extension = os.path.splitext(file_name)

    encrypted_file_path = file_name + '.enc'  # Şifrelenen dosyanın yolunu oluştur
    dosya_adı2 = os.path.basename(encrypted_file_path)
    if os.path.exists(encrypted_file_path):
        while True:
            response = input(f"{Fore.YELLOW}'{dosya_adı2}' already exists. Do you want to overwrite it? (y/n): ").lower()
            if response == 'y':
                break
            elif response == 'n':
                new_file_name = input("Enter the new file name: ")
                encrypted_file_path = os.path.join(os.path.dirname(file_name), new_file_name + file_extension +  '.enc')
                break
            else:
                print(Fore.RED + "Invalid answer! Please enter one of the 'y' or 'n' keys.")

    start_time = time.time()
    try:
        with open(file_name, 'rb') as f, open(encrypted_file_path, 'wb') as outf:
            while chunk := f.read(CHUNK_SIZE):
                if msvcrt.kbhit() and msvcrt.getch() == b'\x1b':  # ESC tuşuna basılıp basılmadığını kontrol eder
                    print(Fore.RED + "Encryption process cancelled.                              \n")
                    raise KeyboardInterrupt  # İşlemi durdurmak için istisna fırlatır

                nonce = random(SecretBox.NONCE_SIZE)
                ciphertext = box.encrypt(chunk, nonce)
                outf.write(ciphertext)
                encrypted_size += len(chunk)
                print_progress(encrypted_size, total_size, start_time)
                
        end_time = time.time()
        elapsed_time = end_time - start_time
        dosya_adı = os.path.basename(file_name)
        file_size = total_size / (1024 * 1024)
        encryption_speed = file_size / elapsed_time
        print(Fore.GREEN + f"{dosya_adı} encrypted in", Fore.CYAN + f"{elapsed_time:.0f}", Fore.GREEN + "seconds. File Size:", Fore.CYAN + f"{file_size:.1f} MB", Fore.GREEN + "Encryption Speed:", Fore.CYAN + f"{encryption_speed:.0f} MB/sn")
        print(Fore.GREEN + "Your key:", Fore.CYAN + password,"\n")

    except KeyboardInterrupt:
        # İşlem iptal edildiğinde oluşturulan dosyayı sil
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)

    except Exception as e:
        print(Fore.RED + f"Error: {e}")
        # Başka bir hata meydana gelirse oluşturulan dosyayı sil
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
            print(Fore.RED + f"{encrypted_file_path} deleted.")


def get_key(password):
    salt = b'specialsalt'  # Salt değeri sabit
    #The salt value is different in the .exe version. You cannot open the file you encrypted with the .exe version with .py!
    key_length = 32  # İstenen anahtar uzunluğu 32 byte = 256 bit
    
    # Parolayı str türüne dönüştür ve ardından bayt dizisine encode et
    password_bytes = password.encode('utf-8')
    
    # Argon2id ile hashleme yap ve belirli uzunlukta anahtar türet
    hashed_password = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=3,          # Iteration count
        memory_cost=65536,    # Memory cost in kibibytes
        parallelism=2,        # Parallelism factor
        hash_len=key_length,  # Desired length of the derived key
        type=Type.ID          # Argon2id
    )
    
    return hashed_password

def generate_random_key(uzunluk):
    import string
    import random
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=uzunluk))
    return password

def decrypt_file(file_name, key):
    
    box = SecretBox(key)
    
    total_size = os.path.getsize(file_name)
    decrypted_size = 0

    decrypted_file_path = file_name[:-4]  # Çözülen dosyanın yolunu oluştur

    dosyam = file_name[:-4]

    file_base_name, file_extension = os.path.splitext(dosyam) # Dosya adından uzantıyı ayır

    dosya_adı3 = os.path.basename(decrypted_file_path)

    if os.path.exists(decrypted_file_path):
        overwrite_decision = input(Fore.YELLOW + f"{dosya_adı3} already exists. Do you want to overwrite it? (y/n): ").strip().lower()
        if overwrite_decision == 'n':
            new_file_name = input("Please enter the new file name: ")
            decrypted_file_path = os.path.join(os.path.dirname(file_name), new_file_name + file_extension)

    successful = False

    start_time = time.time()
    try:
        with open(file_name, 'rb') as f, open(decrypted_file_path, 'wb') as outf:
            while chunk := f.read(CHUNK_SIZE + SecretBox.NONCE_SIZE + SecretBox.MACBYTES):
                if msvcrt.kbhit() and msvcrt.getch() == b'\x1b':  # ESC tuşuna basılıp basılmadığını kontrol eder
                    print(Fore.RED + "Decryption process cancelled.                              \n")
                    raise KeyboardInterrupt  # İşlemi durdurmak için istisna fırlatır
                                
                try:
                    decrypted_data = box.decrypt(chunk)
                    outf.write(decrypted_data)
                    decrypted_size += len(decrypted_data)
                    print_progress(decrypted_size, total_size, start_time)
                except Exception as e:
                    print(Fore.RED + f"Error: {e}")
                    print(Fore.RED + "Make sure your key is correct!\n")
                    raise e  # Hata meydana geldiğinde dıştaki try bloğuna geçer
        successful = True  # Dosya başarıyla çözüldüğünde
    except KeyboardInterrupt:
        # İşlem iptal edildiğinde oluşturulan dosyayı sil
        if os.path.exists(decrypted_file_path):
            os.remove(decrypted_file_path)
    except Exception:
        # Eğer bir hata meydana gelirse, dosyanın silinmesini sağla
        if os.path.exists(decrypted_file_path):
            try:
                os.remove(decrypted_file_path)
            except Exception as remove_error:
                print(Fore.RED + f"File deletion error: {remove_error}")

    if successful:
        end_time = time.time()
        elapsed_time = end_time - start_time
        dosya_adı = os.path.basename(file_name)
        file_size = total_size / (1024 * 1024)
        decryption_speed = file_size / elapsed_time
        print(Fore.GREEN + f"{dosya_adı} decrypted in", Fore.CYAN + f"{elapsed_time:.0f}", Fore.GREEN + "seconds.", Fore.GREEN + "Decryption Speed:", Fore.CYAN + f"{decryption_speed:.0f} MB/sn\n")



def print_progress(current, total, start_time):
    if total == 0:
        print(Fore.RED + "Total value cannot be zero.", end='\r')
        return

    progress = (current / total) * 100
    elapsed_time = time.time() - start_time

    if elapsed_time == 0:
        speed = float('inf')  # Sonsuz
    else:
        speed = (current / (1024 * 1024)) / elapsed_time

    if speed == 0:
        remaining_time = float('inf')  # Sonsuz
    else:
        remaining_time = (total - current) / (1024 * 1024) / speed
#                                                                                                                                 
    print(Fore.YELLOW + f"Progress: {progress:.0f}% - Speed: {speed:.0f} MB/sn - Remaining Time: {remaining_time:.0f} saniye", end='\r')


###########################################################################################################3
# Veritabanı dosyasının yolu
DATABASE_DIR = os.path.join(os.getenv('LOCALAPPDATA'), "Encryption Program")
DATABASE_PATH = os.path.join(DATABASE_DIR, "mlog.db")

def create_database():
    """SQLite veritabanı oluştur"""
    # Veritabanı dizini yoksa oluştur
    if not os.path.exists(DATABASE_DIR):
        os.makedirs(DATABASE_DIR)

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Mesajlar tablosunu oluştur veya güncelle
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            subject TEXT,
            message_text TEXT,
            send_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

def log_message(sender, subject, message):
    """Gönderilen mesajı veritabanına kaydet"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    
    # Mesajı veritabanına ekle
    cursor.execute('''
        INSERT INTO messages (sender, subject, message_text, send_time) VALUES (?, ?, ?, ?)
    ''', (sender, subject, message, current_time))
    
    conn.commit()
    conn.close()

def check_message_count():
    """Veritabanındaki günlük mesaj sayısını kontrol et"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    previous_hour = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - 3600))
    
    cursor.execute('''
        SELECT COUNT(*) FROM messages
        WHERE send_time BETWEEN ? AND ?
    ''', (previous_hour, current_time))
    
    message_count = cursor.fetchone()[0]

    conn.close()

    return message_count
def get_system_info():
    info = {
        'Sistem': platform.system() +" "+platform.release(),  # İşletim sistemi adı
        'Mimari': platform.machine(),  # Makinenin donanım türü
        'Ağ Adı': platform.node(),  # Ağdaki bilgisayar adı
        'Python Sürümü': platform.python_version(),  # Python sürümü
    }
    system_info = "\n".join([f"{key}: {value}" for key, value in info.items()])
    return system_info


async def send_telegram_message(subject, message, file_path=None):
    BOT_TOKEN = 'please use .exe version to send messages'  # Bot API
    CHAT_ID = ''  # Botun mesaj göndereceği Telegram kullanıcı ID'si
    bot = Bot(token=BOT_TOKEN)

    
    system_info = get_system_info()
    full_message = (
        f"<b>Gönderen:</b> {sender}\n"
        f"<b>Konu:</b> <i>{subject}</i>\n"
        f"<b>Mesaj:</b> <i>{message}</i>\n"
        f"<b>Sistem Bilgileri:</b>\n<pre>{system_info}</pre>"
    )


    try:
        if file_path:
            with open(file_path, 'rb') as file:
                await bot.send_document(chat_id=CHAT_ID, document=file, caption=full_message, parse_mode='HTML')
        else:
            await bot.send_message(chat_id=CHAT_ID, text=full_message, parse_mode='HTML')
        log_message(sender, subject, message)
        print(Fore.GREEN + "Your message has been shared with the producer!\n")
    except TelegramAPIError as e:
        print(Fore.RED + f"Hata: {e}\n")
    finally:
        await bot.session.close()


# Kullanıcı girişini işle
async def get_user_input():
    global sender
    while True:
        sender = input(Fore.CYAN + "From: " + Fore.WHITE)
        if not sender.strip():
            print(Fore.RED + "Error: Sender cannot be empty!")
        elif len(sender) > 128:
            print(Fore.RED + "Error: Sender cannot be longer than 128 characters!")
        else:
            break
    while True:
        subject = input(Fore.CYAN + "Subject: " + Fore.WHITE)
        if len(subject) > 64:
            print(Fore.RED + "Error: Subject cannot be longer than 64 characters!")
        else:
            break
    while True:
        message = input(Fore.CYAN + "Message: " + Fore.WHITE)
        if not message.strip():
            print(Fore.RED + "Error: The message cannot be empty!")
        elif len(message) > 4096:
            print(Fore.RED + "Error: Message cannot be longer than 4096 characters!")
        else:
            break
    file_choice = input("Do you want to attach a file to your message?(Max 16MB)(y/n): ").lower()
    if file_choice == 'y':
        file_path = dosya_sec3()
        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        if file_size > 32 * 1024 * 1024:  # 16 MB'den büyükse
            print(Fore.RED + "File size greater than 16MB! Could not attach file.\n")
        else:
            print(Fore.CYAN + "Selected file:",Fore.WHITE +  filename)
            print(Fore.GREEN + "Sending message...", end='\r')
            await send_telegram_message(subject, message, file_path)
    else:
        print(Fore.GREEN + "Sending message...", end='\r')
        await send_telegram_message(subject, message)

# Ana işlev
async def main():
    create_database()
    message_count = check_message_count()
    if message_count > 2:
        print(Fore.RED + "You have reached the message limit. Please try again later.\n")
    else: 
        remaining_messages = 3 - message_count
        print(Fore.GREEN + "Checking the Internet connection...", end='\r')
        if await check_internet_connection():
            print(Fore.YELLOW + "You are about to send a message to the producers telegram account. Please do not send messages in vain!")
            print(Fore.CYAN + f"Your remaining hourly message allowance: {Fore.GREEN}{remaining_messages}")
            continue_choice = input("Do you want to continue? (y/n): "+ Fore.WHITE).lower()
            if continue_choice == "y":
                await get_user_input()
            else:
                print(Fore.RED + "Message sending cancelled!\n")
        else:
            print(Fore.RED + "Internet connection not found!         \n")

async def check_internet_connection():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://www.google.com') as response:
                return response.status == 200
    except aiohttp.ClientConnectorError:
        return False

def list_messages():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    while True:
        try:
            message_count = int(input("How many messages do you want to display: "))
            print("")
            if message_count <= 0:
                print(Fore.RED + "Error: Please enter a positive number.")
            else:
                break
        except ValueError:
            print(Fore.RED + "Error: You entered an invalid value. Please enter a number.")

    cursor.execute('''
        SELECT sender, subject, message_text, strftime('%d/%m/%Y %H:%M:%S', send_time) FROM messages
    ''')

    # Belirlenen sayıda mesajı al
    messages = cursor.fetchmany(message_count)

    conn.close()

    for i, message in enumerate(messages, 1):
        print(f"{Fore.YELLOW}MESSAGE {i} - {message[3]}\n{Fore.GREEN}From: {Fore.CYAN}{message[0]}   {Fore.GREEN}Subject: {Fore.CYAN}{message[1]}\n{Fore.GREEN}Message: {Fore.CYAN}{message[2]}\n")

###############################################################################
CYAN = "\033[36m"

banner = f"""{CYAN} 
┌─┐┌┐┌┌─┐┬─┐┬ ┬┌─┐┌┬┐┬┌─┐┌┐┌  ┌─┐┬─┐┌─┐┌─┐┬─┐┌─┐┌┬┐
├┤ ││││  ├┬┘└┬┘├─┘ │ ││ ││││  ├─┘├┬┘│ ││ ┬├┬┘├─┤│││
└─┘┘└┘└─┘┴└─ ┴ ┴   ┴ ┴└─┘┘└┘  ┴  ┴└─└─┘└─┘┴└─┴ ┴┴ ┴"""                                                                                                                           
tablo = f"""
╔═══════════════════╤═══════════════════╗
║ 1- Encrypt        │ 5- How it works   ║
╟───────────────────┼───────────────────╢
║ 2- Decrypt        │ 6- Producer       ║
╟───────────────────┼───────────────────╢
║ 3- Set chunk size │ 7- Send message to║
║                   │    producer       ║
╟───────────────────┼───────────────────║
║ 4- Verify file    │ 8- Exit           ║
║    integrity      │                   ║
╚═══════════════════════════════════════╝"""

print(banner)
print(tablo)
while True:
    try:
        choice = input(Fore.MAGENTA + "Choice:" + Fore.WHITE)
        if choice == "1":
            dosya = dosya_sec()
            dosya_adı = os.path.basename(dosya)
            print("Selected file:", dosya_adı)
            total_size = os.path.getsize(dosya)
            file_size = total_size / (1024 * 1024)
            if file_size <= 256:
                hash = calculate_hash2(dosya)
                print("Selected file hash value:", hash)
            password = input("Please enter the encryption key: ")
            if password.startswith('/generatekey'):
                uzunluk = int(password.split("/generatekey")[1])  # Girişteki sayıyı almak için bölme işlemi yapılıyor.
                password = generate_random_key(uzunluk)
            key = get_key(password)
            encrypt_file(dosya, key)
        elif choice == "2":
            dosya = dosya_sec1()
            dosya_adı = os.path.basename(dosya)
            print("Selected file:", dosya_adı)
            password = input("Please enter the decryption key: ")
            key = get_key(password)
            decrypt_file(dosya, key)
        elif choice == "5":
            print("*This programme encrypts the selected file using the XChaCha20-Poly1305 encryption algorithm. It converts the password you enter into a 256Bit key using argon2 KDF algorithm.")
            print("*During encryption or decryption operations, you can press ESC to cancel the operation.")
            print("*You can set the chunk size depending on the file size. By default it is 2 MB.")
            print("*If the selected file is smaller than 256MB, the hash value is automatically printed. You can then use this to verify file integrity after decryption.")
            print("*To generate a random key, simply type /generatekey[x] in the section where the key is asked. Instead of [x] you should type character length.")
            print("*If you want to send feedback to the producer about the program, you can use the '7' option. You can write a message at any time. Please do not write unnecessary and meaningless messages and do not disturb :)")
            print("*When sending a message, you also share some system information with the producer that does NOT contain personal data (operating system, python version, processor and architecture.)")
            print("*You are allowed to send 3 messages per hour. Select '7db' to see your message history.")
            print("*If you want me to return the messages you send, you can write your telegram username with @ at the beginning in the 'From' section. You can also write your e-mail address if you want. If you do not want me to return, you can only write your name.\n")
        elif choice == "6":
            print("Producer: Ahmet Emre\nGithub: ahmetemre3829\nTelegram: Select '7' to send a message.\nVersion: 3.6.3\n26/05/2024\n")
        elif choice == "3":
            try:
                chunk_input = input("Enter the desired chunk size in MB: ")
                CHUNK_SIZE = int(chunk_input) * 1024 * 1024 if chunk_input else DEFAULT_CHUNK_SIZE
                print(Fore.GREEN + "Chunk size set to",Fore.CYAN + f"{CHUNK_SIZE / (1024 * 1024):.0f}", Fore.GREEN + "MB.\n")
            except ValueError:
                print(Fore.RED + "Incorrect entry! Chunk size set to 2 MB.\n")
                CHUNK_SIZE = DEFAULT_CHUNK_SIZE
#-----------------------------------------------------------------------------------------------------------------
        elif choice == "4":
            print("\n\n\n")
            print(Fore.BLUE + Style.BRIGHT + "DOSYA BÜTÜNLÜĞÜ DOĞRULAMA - SHA256")
            print("\n1- Calculate hash value\n2- Compare hash value with file\n3- Compare two hash values\n4- Set chunk size\n5- Back to main menu\n")
            while True:
                try:
                    inner_choice = input(Fore.MAGENTA + "Choice:" + Fore.WHITE)
                    if inner_choice == "1":
                       dosyas = dosya_sec2()
                       dosya_adı = os.path.basename(dosyas)
                       print(Fore.GREEN + "Selected file:", dosya_adı)
                       hash = calculate_hash(dosyas)
                       print(Fore.GREEN + "SHA-256 hash value:",Fore.CYAN + hash, "\n")
                    if inner_choice == "2":
                        dosyas = dosya_sec2()
                        dosya_adı = os.path.basename(dosyas)
                        print("Selected file:", dosya_adı)
                        sha = input("Enter the hash value you want to compare: ")
                        hash = calculate_hash(dosyas)
                        if sha == hash:                                                                  
                            print(Fore.GREEN + "Hash values match. File verified!                            \n")
                        else:
                            print(Fore.RED + "Hash values do not match. File could not be verified!          \n")    
                    if inner_choice == "3":
                        hash1 = input("Enter the first hash value: ")
                        hash2 = input("Enter the second hash value: ")   
                        if hash1 == hash2:
                            print(Fore.GREEN + "Hash values match!\n")
                        else:
                            print(Fore.RED + "Hash values do not match!\n")    
                    if inner_choice == "4":
                        try:
                            chunk_input2 = input("Enter the desired chunk size in MB: ")
                            if chunk_input2.strip():  # Boş giriş kontrolü
                                CHUNK_SIZE2 = int(chunk_input2) * 1024 * 1024  # MB cinsinden girdiyi byte'a çevirme
                            else:
                                CHUNK_SIZE2 = DEFAULT_CHUNK_SIZE2
                            print(Fore.GREEN + "Chunk size set to", Fore.CYAN + f"{CHUNK_SIZE2 / (1024 * 1024):.0f}", Fore.GREEN + "MB.\n")
                        except ValueError:
                            CHUNK_SIZE2 = DEFAULT_CHUNK_SIZE2
                            print(Fore.RED + "Incorrect input! Chunk size set to 1MB.\n")
                    if inner_choice == "5":
                        print("\n\n\n")
                        print(banner)
                        print(tablo)
                        break
                except FileNotFoundError:
                    print(Fore.RED + "Error: File not found!\n")                  
                except Exception as e:
                    print(Fore.RED + f"Error: {e}\n")
#-----------------------------------------------------------------------------------------------------------------
        elif choice == "7":
            asyncio.run(main())
        elif choice == "7db":
           list_messages()
        elif choice == "8":
            break
        else:
            print(Fore.RED + "Please make a valid choice!")
    except FileNotFoundError:
        print(Fore.RED + "Error: File not found!\n")
    except Exception as e:
        print(Fore.RED + f"Error: {e}\n")
