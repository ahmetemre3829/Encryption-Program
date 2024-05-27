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
    dosya_yolu = filedialog.askopenfilename(title="Şifrelemek istediğiniz dosyayı seçin")
    return dosya_yolu

def dosya_sec1():
    root = tk.Tk()
    root.withdraw()
    dosya_yolu = filedialog.askopenfilename(title="Şifresini çözmek istediğiniz dosyayı seçin")
    return dosya_yolu

def dosya_sec2():
    root = tk.Tk()
    root.withdraw()
    dosya_yolu = filedialog.askopenfilename(title="SHA-256 hash değeri hesaplamak için dosya seçin")
    return dosya_yolu

def dosya_sec3():
    root = tk.Tk()
    root.withdraw()
    dosya_yolu = filedialog.askopenfilename(title="Yapımcıya göndermek istediğiniz dosyayı seçin")
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
            response = input(f"{Fore.YELLOW}'{dosya_adı2}' adında bir dosya zaten var. Üzerine yazmak istiyor musunuz? (e/h): ").lower()
            if response == 'e':
                break
            elif response == 'h':
                new_file_name = input("Yeni dosya adını girin: ")
                encrypted_file_path = os.path.join(os.path.dirname(file_name), new_file_name + file_extension +  '.enc')
                break
            else:
                print(Fore.RED + "Geçersiz yanıt! Lütfen 'e' veya 'h' tuşlarından birini girin.")

    start_time = time.time()
    try:
        with open(file_name, 'rb') as f, open(encrypted_file_path, 'wb') as outf:
            while chunk := f.read(CHUNK_SIZE):
                if msvcrt.kbhit() and msvcrt.getch() == b'\x1b':  # ESC tuşuna basılıp basılmadığını kontrol eder
                    print(Fore.RED + "Şifreleme işlemi iptal edildi.                      \n")
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
        print(Fore.GREEN + f"{dosya_adı}", Fore.CYAN + f"{elapsed_time:.0f}", Fore.GREEN + "saniyede şifrelendi. Dosya Boyutu:", Fore.CYAN + f"{file_size:.1f} MB", Fore.GREEN + "Şifreleme Hızı:", Fore.CYAN + f"{encryption_speed:.0f} MB/sn")
        print(Fore.GREEN + "Anahtarınız:", Fore.CYAN + password,"\n")

    except KeyboardInterrupt:
        # İşlem iptal edildiğinde oluşturulan dosyayı sil
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)

    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
        # Başka bir hata meydana gelirse oluşturulan dosyayı sil
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
            print(Fore.RED + f"{encrypted_file_path} silindi.")


def get_key(password):
    salt = b'specialsalt'  # Salt değeri sabit
    #Salt değeri .exe versiyonunda farklıdır. Exe versiyonu ile şifrelediğiniz dosyayı .py ile açamazsınız!
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
        overwrite_decision = input(Fore.YELLOW + f"{dosya_adı3} adında bir dosya zaten var. Üzerine yazılsın mı? (e/h): ").strip().lower()
        if overwrite_decision == 'h':
            new_file_name = input("Lütfen yeni dosya adını girin: ")
            decrypted_file_path = os.path.join(os.path.dirname(file_name), new_file_name + file_extension)

    successful = False

    start_time = time.time()
    try:
        with open(file_name, 'rb') as f, open(decrypted_file_path, 'wb') as outf:
            while chunk := f.read(CHUNK_SIZE + SecretBox.NONCE_SIZE + SecretBox.MACBYTES):
                if msvcrt.kbhit() and msvcrt.getch() == b'\x1b':  # ESC tuşuna basılıp basılmadığını kontrol eder
                    print(Fore.RED + "Şifre çözme işlemi iptal edildi.                     \n")
                    raise KeyboardInterrupt  # İşlemi durdurmak için istisna fırlatır
                                
                try:
                    decrypted_data = box.decrypt(chunk)
                    outf.write(decrypted_data)
                    decrypted_size += len(decrypted_data)
                    print_progress(decrypted_size, total_size, start_time)
                except Exception as e:
                    print(Fore.RED + f"Hata: {e}")
                    print(Fore.RED + "Şifreleme anahtarınızın doğru olduğundan emin olun!\n")
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
                print(Fore.RED + f"Dosya silme hatası: {remove_error}")

    if successful:
        end_time = time.time()
        elapsed_time = end_time - start_time
        dosya_adı = os.path.basename(file_name)
        file_size = total_size / (1024 * 1024)
        decryption_speed = file_size / elapsed_time
        print(Fore.GREEN + f"{dosya_adı}", Fore.CYAN + f"{elapsed_time:.0f}", Fore.GREEN + "saniyede şifresi çözüldü.", Fore.GREEN + "Şifre Çözme Hızı:", Fore.CYAN + f"{decryption_speed:.0f} MB/sn\n")



def print_progress(current, total, start_time):
    if total == 0:
        print(Fore.RED + "Toplam değer sıfır olamaz.", end='\r')
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

    print(Fore.YELLOW + f"İlerleme: {progress:.0f}% - Hız: {speed:.0f} MB/sn - Kalan Süre: {remaining_time:.0f} saniye", end='\r')


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
    BOT_TOKEN = 'Mesaj göndermek için lütfen .exe versiyonunu kullanın'  # Bot API
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
        print(Fore.GREEN + "Mesajınız yapımcıyla paylaşıldı!\n")
    except TelegramAPIError as e:
        print(Fore.RED + f"Hata: {e}\n")
    finally:
        await bot.session.close()


# Kullanıcı girişini işle
async def get_user_input():
    global sender
    while True:
        sender = input(Fore.CYAN + "Gönderen: " + Fore.WHITE)
        if not sender.strip():
            print(Fore.RED + "Hata: Gönderen boş olamaz!")
        elif len(sender) > 128:
            print(Fore.RED + "Hata: Gönderen 128 karakterden uzun olamaz!")
        else:
            break
    while True:
        subject = input(Fore.CYAN + "Konu: " + Fore.WHITE)
        if len(subject) > 64:
            print(Fore.RED + "Hata: Konu 64 karakterden uzun olamaz!")
        else:
            break
    while True:
        message = input(Fore.CYAN + "Mesaj: " + Fore.WHITE)
        if not message.strip():
            print(Fore.RED + "Hata: Mesaj boş olamaz!")
        elif len(message) > 4096:
            print(Fore.RED + "Hata: Mesaj 4096 karakterden uzun olamaz!")
        else:
            break
    file_choice = input("Mesajınıza dosya eklemek istiyor musunuz?(Max 16MB)(e/h): ").lower()
    if file_choice == 'e':
        file_path = dosya_sec3()
        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        if file_size > 32 * 1024 * 1024:  # 16 MB'den büyükse
            print(Fore.RED + "Dosya boyutu 16MB'den büyük! Dosya eklenemedi.\n")
        else:
            print(Fore.CYAN + "Seçilen dosya:",Fore.WHITE +  filename)
            print(Fore.GREEN + "Mesaj gönderiliyor...", end='\r')
            await send_telegram_message(subject, message, file_path)
    else:
        print(Fore.GREEN + "Mesaj gönderiliyor...", end='\r')
        await send_telegram_message(subject, message)

# Ana işlev
async def main():
    create_database()
    message_count = check_message_count()
    if message_count > 2:
        print(Fore.RED + "Mesaj sınırına ulaştınız. Lütfen daha sonra tekrar deneyin.\n")
    else: 
        remaining_messages = 3 - message_count
        print(Fore.GREEN + "İnternet bağlantısı kontrol ediliyor...", end='\r')
        if await check_internet_connection():
            print(Fore.YELLOW + "Yapımcının telegram hesabına mesaj göndermek üzeresiniz. Lütfen boş yere mesaj göndermeyin!")
            print(Fore.CYAN + f"Kalan saatlik mesaj gönderme hakkınız: {Fore.GREEN}{remaining_messages}")
            continue_choice = input("Devam etmek istiyor musunuz? (e/h): "+ Fore.WHITE).lower()
            if continue_choice == "e":
                await get_user_input()
            else:
                print(Fore.RED + "Mesaj gönderme iptal edildi!\n")
        else:
            print(Fore.RED + "İnternet bağlantısı bulunamadı!        \n")

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
            message_count = int(input("Kaç mesaj görüntülemek istiyorsunuz: "))
            print("")
            if message_count <= 0:
                print(Fore.RED + "Hata: Lütfen pozitif bir sayı girin.")
            else:
                break
        except ValueError:
            print(Fore.RED + "Hata:Geçersiz bir değer girdiniz. Lütfen bir sayı girin.")

    cursor.execute('''
        SELECT sender, subject, message_text, strftime('%d/%m/%Y %H:%M:%S', send_time) FROM messages
    ''')

    # Belirlenen sayıda mesajı al
    messages = cursor.fetchmany(message_count)

    conn.close()

    for i, message in enumerate(messages, 1):
        print(f"{Fore.YELLOW}MESAJ {i} - {message[3]}\n{Fore.GREEN}Gönderen: {Fore.CYAN}{message[0]}   {Fore.GREEN}Konu: {Fore.CYAN}{message[1]}\n{Fore.GREEN}Mesaj: {Fore.CYAN}{message[2]}\n")

###############################################################################
CYAN = "\033[36m"

banner = f"""{CYAN} 
┌─┐┬┌─┐┬─┐┌─┐┬  ┌─┐┌┬┐┌─┐  ┌─┐┬─┐┌─┐┌─┐┬─┐┌─┐┌┬┐┬
└─┐│├┤ ├┬┘├┤ │  ├┤ │││├┤   ├─┘├┬┘│ ││ ┬├┬┘├─┤││││
└─┘┴└  ┴└─└─┘┴─┘└─┘┴ ┴└─┘  ┴  ┴└─└─┘└─┘┴└─┴ ┴┴ ┴┴"""                                                                                                                           
tablo = f"""
╔═══════════════════╤═══════════════════╗
║ 1- Şifrele        │ 5- Nasıl çalışır  ║
╟───────────────────┼───────────────────╢
║ 2- Şifre Çöz      │ 6- Yapımcı        ║
╟───────────────────┼───────────────────╢
║ 3- Chunk boyutu   │ 7- Yapımcıya mesaj║
║    ayarla         │    gönder         ║
╟───────────────────┼───────────────────║
║ 4- Dosya bütünlüğü│ 8- Çıkış          ║
║    doğrula        │                   ║
╚═══════════════════════════════════════╝"""

print(banner)
print(tablo)
while True:
    try:
        choice = input(Fore.MAGENTA + "Seçiminiz:" + Fore.WHITE)
        if choice == "1":
            dosya = dosya_sec()
            dosya_adı = os.path.basename(dosya)
            print("Seçilen dosya:", dosya_adı)
            total_size = os.path.getsize(dosya)
            file_size = total_size / (1024 * 1024)
            if file_size <= 256:
                hash = calculate_hash2(dosya)
                print("Seçilen dosya hash değeri:", hash)
            password = input("Lütfen şifreleme anahtarı girin: ")
            if password.startswith('/anahtaroluştur'):
                uzunluk = int(password.split("/anahtaroluştur")[1])  # Girişteki sayıyı almak için bölme işlemi yapılıyor.
                password = generate_random_key(uzunluk)
            key = get_key(password)
            encrypt_file(dosya, key)
        elif choice == "2":
            dosya = dosya_sec1()
            dosya_adı = os.path.basename(dosya)
            print("Seçilen dosya:", dosya_adı)
            password = input("Lütfen şifre çözme anahtarını girin: ")
            key = get_key(password)
            decrypt_file(dosya, key)
        elif choice == "5":
            print("*Bu program seçilen dosyayı XChaCha20-Poly1305 şifreleme algoritmasını kullanarak şifreler. Girdiğiniz parolayı argon2 KDF algoritması kullanarak 256Bit anahtara dönüştürür.")
            print("*Şifreleme veya çözme işlemleri sırasında işlemi iptal etmek için ESC basabilirsiniz.")
            print("*Dosya büyüklüğüne bağlı olarak chunk boyutunu ayarlayabilirsniz. Varsayılan olarak 2 MBtır.")
            print("*Eğer seçilen dosya 256MBtan daha küçükse hash değeri otomatik olarak yazdırılır. Bunu daha sonra şifre çözme işleminden sonra dosya bütünlüğü doğrulamak için kullanabilirsiniz.")
            print("*Rastgele anahtar oluşturmak için anahtar sorulduğu kısımda /anahtaroluştur[x] yazmanız yeterlidir. [x] yerine karakter uzunluğu yazmalısınız.")
            print("*Yapımcıya programla ilgili geri dönüş yapmak isterseniz '7' seçeneğini kullanabilirsiniz. İstediğiniz zaman mesaj yazabilirsiniz. Lütfen gereksiz ve anlamsız mesajlar yazıp rahatsız etmeyin :)")
            print("*Mesaj gönderirken aynı zamanda kişisel veri İÇERMEYEN bazı sistem bilgilerini de yapımcıyla paylaşırsınız.(İşletim sistemi, python sürümü, işlemci ve mimari.)")
            print("*Mesaj gönderme hakkınız saatte 3 adettir. Mesaj geçmişinizi görmek için '7db' seçeneğini seçin.")
            print("*Eğer gönderdiğiniz mesajlara geri dönüş yapmamı istiyorsanız 'Gönderen' kısmına telegram kullanıcı adınızı başında @ olacak şekilde yazabilirsiniz. İsterseniz mail adresinizide yazabilirsiniz. Dönüş yapmamı istemezseniz sadece adınızı yazabilirsiniz.\n")
        elif choice == "6":
            print("Yapımcı: Ahmet Emre\nGithub: ahmetemre3829\nTelegram: Mesaj göndermek için '7' seçin.\nVersiyon: 3.6.3\n26/05/2024\n")
        elif choice == "3":
            try:
                chunk_input = input("İstediğiniz chunk boyutunu MB cinsinden girin: ")
                CHUNK_SIZE = int(chunk_input) * 1024 * 1024 if chunk_input else DEFAULT_CHUNK_SIZE
                print(Fore.GREEN + "Chunk boyutu",Fore.CYAN + f"{CHUNK_SIZE / (1024 * 1024):.0f}", Fore.GREEN + "MB olarak ayarlandı.\n")
            except ValueError:
                print(Fore.RED + "Hatalı giriş! Chunk boyutu 2 MB olarak ayarlandı.\n")
                CHUNK_SIZE = DEFAULT_CHUNK_SIZE
#-----------------------------------------------------------------------------------------------------------------
        elif choice == "4":
            print("\n\n\n")
            print(Fore.BLUE + Style.BRIGHT + "DOSYA BÜTÜNLÜĞÜ DOĞRULAMA - SHA256")
            print("\n1- Hash değeri hesapla\n2- Dosya ile hash değeri karşılaştır\n3- İki hash değerini karşılaştır\n4- Chunk boyutunu ayarla\n5- Ana menüye dön\n")
            while True:
                try:
                    inner_choice = input(Fore.MAGENTA + "Seçiminiz:" + Fore.WHITE)
                    if inner_choice == "1":
                       dosyas = dosya_sec2()
                       dosya_adı = os.path.basename(dosyas)
                       print(Fore.GREEN + "Seçilen dosya:", dosya_adı)
                       hash = calculate_hash(dosyas)
                       print(Fore.GREEN + "SHA-256 hash değeri:",Fore.CYAN + hash, "\n")
                    if inner_choice == "2":
                        dosyas = dosya_sec2()
                        dosya_adı = os.path.basename(dosyas)
                        print("Seçilen dosya:", dosya_adı)
                        sha = input("Karşılaştırmak istediğiniz hash değerini girin: ")
                        hash = calculate_hash(dosyas)
                        if sha == hash:
                            print(Fore.GREEN + "Hash değerleri eşleşiyor. Dosya doğrulandı!            \n")
                        else:
                            print(Fore.RED + "Hash değerleri eşleşmiyor. Dosya doğrulanamadı!         \n")    
                    if inner_choice == "3":
                        hash1 = input("İlk hash değerini girin: ")
                        hash2 = input("İkinci hash değerini girin: ")   
                        if hash1 == hash2:
                            print(Fore.GREEN + "Hash değerleri eşleşiyor!\n")
                        else:
                            print(Fore.RED + "Hash değerleri eşleşmiyor!\n")    
                    if inner_choice == "4":
                        try:
                            chunk_input2 = input("İstediğiniz chunk boyutunu MB cinsinden girin: ")
                            if chunk_input2.strip():  # Boş giriş kontrolü
                                CHUNK_SIZE2 = int(chunk_input2) * 1024 * 1024  # MB cinsinden girdiyi byte'a çevirme
                            else:
                                CHUNK_SIZE2 = DEFAULT_CHUNK_SIZE2
                            print(Fore.GREEN + "Chunk boyutu", Fore.CYAN + f"{CHUNK_SIZE2 / (1024 * 1024):.0f}", Fore.GREEN + "MB olarak ayarlandı.\n")
                        except ValueError:
                            CHUNK_SIZE2 = DEFAULT_CHUNK_SIZE2
                            print(Fore.RED + "Hatalı giriş! Chunk boyutu 1MB olarak ayarlandı.\n")
                    if inner_choice == "5":
                        print("\n\n\n")
                        print(banner)
                        print(tablo)
                        break
                except FileNotFoundError:
                    print(Fore.RED + "Hata: Dosya bulunamadı!\n")                  
                except Exception as e:
                    print(Fore.RED + f"Hata: {e}\n")
#-----------------------------------------------------------------------------------------------------------------
        elif choice == "7":
            asyncio.run(main())
        elif choice == "7db":
           list_messages()
        elif choice == "8":
            break
        else:
            print(Fore.RED + "Lütfen geçerli bir seçim yapın!")
    except FileNotFoundError:
        print(Fore.RED + "Hata: Dosya bulunamadı!\n")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}\n")