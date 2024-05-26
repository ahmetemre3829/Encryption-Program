# Proje Hakkında
## İlk Bakış
Bu proje, kullanıcıların dosyalarını güvenli bir şekilde şifrelemelerini ve şifre çözmelerini sağlayan bir Python uygulamasıdır. Program, XChaCha20-Poly1305 şifreleme algoritmasını kullanarak dosyaları şifreler ve argon2 KDF algoritması ile 256 bit uzunluğunda bir anahtar türetir. Ayrıca, dosyaların bütünlüğünü doğrulamak için SHA-256 hash hesaplama özelliği de sunar.

## Özellikler
* Dosya Şifreleme: 
Kullanıcının seçtiği dosyayı şifreler ve şifreli dosyayı .enc uzantısıyla kaydeder. 
* Dosya Şifre Çözme: Kullanıcının seçtiği şifreli dosyanın şifresini çözer. 
* Dosya Bütünlüğü Doğrulama: Dosyaların SHA-256 hash değerlerini hesaplar ve karşılaştırır. 
* Chunk Boyutu Ayarlama: İşlemler sırasında kullanılacak chunk boyutunu MB cinsinden ayarlayabilme. 
* Rastgele Anahtar Oluşturma: Kullanıcıya belirli bir uzunlukta rastgele bir anahtar oluşturma imkanı sunar.
* Yapımcıya mesaj gönder: Yapımcıya geri dönüş sağlamınıza imkan tanır.

## Gereksinimler 
Bu programın çalışması için aşağıdaki Python kütüphanelerine ihtiyaç vardır:

* nacl: PyNaCl kütüphanesi, XChaCha20-Poly1305 şifreleme algoritması için gereklidir. 
* tkinter: GUI bileşenleri ve dosya seçme işlemleri için gereklidir. 
* colorama: Terminalde renkli çıktılar için kullanılır. 
* hashlib: SHA-256 hash hesaplama için gereklidir. 
* argon2: argon2 KDF algoritması için gereklidir. 
* msvcrt: Klavye girdi kontrolü için kullanılır (yalnızca Windows sistemlerde çalışır). Ayrıca, Python 3.8 veya daha üst bir sürümünün yüklü olması gerekmektedir.

## Kurulum 
Gerekli kütüphaneleri yüklemek için aşağıdaki komutları kullanabilirsiniz:

pip install pynacl, pip install colorama, pip install argon2-cffi ...

## Kullanım 
Program, terminal üzerinden çalıştırılabilir. Çalıştırıldığında, kullanıcıya çeşitli seçenekler sunar:

* Şifrele: 
Şifrelenecek dosyayı seçer ve şifreler. 
* Şifre Çöz: 
Şifreli dosyanın şifresini çözer. 
* Chunk Boyutu Ayarla: 
Şifreleme ve şifre çözme işlemlerinde kullanılacak chunk boyutunu ayarlar. 
* Dosya Bütünlüğü Doğrula: Dosyaların SHA-256 hash değerlerini hesaplar ve karşılaştırır. 
* Nasıl Çalışır?: 
Programın nasıl çalıştığını açıklar. 
* Yapımcı: Programın yapımcısı hakkında bilgi verir.
* Yapımcıyla mesaj gönder:
Yapımcıya geri bildirim bırakmanızı sağlar.
* Çıkış: 
Programdan çıkar.

* Anahtar Oluşturma:
Program, kullanıcıdan bir şifreleme anahtarı ister. Kullanıcı, /anahtaroluştur[x] komutunu girerek belirli uzunlukta rastgele bir anahtar oluşturabilir. Örneğin, /anahtaroluştur16 komutu 16 karakter uzunluğunda bir anahtar oluşturur.

* Chunk Boyutu Ayarlama: 
Kullanıcı, chunk boyutunu MB cinsinden ayarlayabilir. Varsayılan olarak, şifreleme ve şifre çözme işlemleri için chunk boyutu 2 MB olarak ayarlanmıştır.

* Dosya Bütünlüğü Doğrulama: Kullanıcı, dosya bütünlüğünü doğrulamak için dosyanın SHA-256 hash değerini hesaplayabilir ve daha sonra bu değeri karşılaştırabilir. Bu özellik, dosyaların değiştirilip değiştirilmediğini kontrol etmek için kullanışlıdır.

## Örnek Kullanım 
Şifreleme Programı çalıştırın ve "1" tuşuna basarak şifreleme seçeneğini seçin. Şifrelenecek dosyayı seçin. Şifreleme anahtarını girin (veya /anahtaroluştur[x] komutunu kullanarak rastgele bir anahtar oluşturun). Şifreleme işlemi tamamlandığında, şifreli dosya aynı dizine .enc uzantısı ile kaydedilir. Şifre Çözme Programı çalıştırın ve "2" tuşuna basarak şifre çözme seçeneğini seçin. Şifresi çözülecek dosyayı seçin. Şifre çözme anahtarını girin. Şifre çözme işlemi tamamlandığında, çözülen dosya aynı dizine kaydedilir.

## Lisans 
Bu proje MIT lisansı altında lisanslanmıştır. Ayrıntılar için LICENSE dosyasına bakın.
