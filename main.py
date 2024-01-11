import os
import magic
import numpy as np
import readline
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class Window:
    def __init__(self, start, end):
        self.start = start
        self.end = end

class SlidingWindow:
    def __init__(self, size):
        self.size = size
        self.data = []
        self.max_segment = []
        self.borders = []

    def slide(self, value):
        self.data.append(value)
        if len(self.data) > self.size:
            self.data.pop(0)

    def close(self):
        max_value = max(self.data)
        self.max_segment = self.data
        self.borders = [i for i, v in enumerate(self.data) if v == max_value]

    def get_max_value(self):
        return max(self.data)

    def get_max_segment(self):
        return self.max_segment

    def get_borders(self):
        return self.borders

def read_bytes(file_path, miss, observed_frequency):
    buffer_size = 2048 * 1024
    size = os.path.getsize(file_path)
    round_count = size // buffer_size + 1
    with open(file_path, 'rb') as fd:
        for _ in range(round_count):
            buffer = fd.read(buffer_size)
            for byte in buffer:
                observed_frequency[byte % 256] += 1

def calc_entropy(miss, observed_frequency, size):
    length = size - miss
    H = 0.0
    for byte_count in observed_frequency:
        p = byte_count / length
        if p:
            H -= p * np.log2(p)
    return H

def calc_X2_entropy(miss, file_path):
    possibilities = 256
    expected = (os.path.getsize(file_path) - miss) / possibilities
    observed_frequency = np.zeros(256, dtype=int)
    read_bytes(file_path, miss, observed_frequency)
    chi = np.sum((observed_frequency - expected) ** 2 / expected)
    entropy = calc_entropy(miss, observed_frequency, os.path.getsize(file_path))
    if  163.0 < chi < 373.0:
        return entropy, chi
    else:
        return 0, 0

def grid_mapping(file_path, miss, window_size):
    buffer_size = 2048 * 1024
    size = os.path.getsize(file_path)
    round_count = size // buffer_size + 1
    grid_size = size // window_size
    grid = np.zeros(grid_size, dtype=float)
    with open(file_path, 'rb') as fd:
        for _ in range(round_count):
            buffer = fd.read(buffer_size)
            if buffer:
                buffer_array = np.frombuffer(buffer, dtype=np.uint8, count=len(buffer))
                min_len = min(len(buffer_array), len(grid))
                grid[:min_len] += buffer_array[:min_len]
    return grid

def wavelet_convolution(file_path, miss, window_size, a):
    p = grid_mapping(file_path, miss, window_size)
    k = 1 / np.sqrt(a)
    W_values = np.convolve(p, [np.sign(t - a/2) for t in range(a)], mode='valid') * k
    max_wavelet = np.max(np.abs(W_values))
    return max_wavelet

def check_system_certificates():
    cert_paths = [
        '/etc/ssl/certs',
        '/etc/pki/tls/certs',
    ]
    found_certificates = False
    for cert_path in cert_paths:
        if os.path.exists(cert_path):
            for cert_file in os.listdir(cert_path):
                full_path = os.path.join(cert_path, cert_file)
                if os.path.isfile(full_path):
                    check_ssl_certificate(full_path)
                    found_certificates = True
    return found_certificates

def check_ssl_certificate(path_to_certificate):
    try:
        with open(path_to_certificate, 'rb') as cert_file:
            cert_data = cert_file.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    except Exception as e:
        print(f"Ошибка СКЗИ: {e}")

def collect_encrypted_files(directory_path):
    magic_obj = magic.Magic()
    encrypted_files = {}
    for root, dirs, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            file_signature = magic_obj.from_file(file_path)
            if any(ext.upper() in file_signature.upper() for ext in ["ZIP", "GPG", "PGP", "PKCS7", "ASN.1", "OPENPGP",
                                                                            "RAR", "7Z", "TAR", "XZ", "GZIP"]):
                        with open(file_path, "rb") as file:
                            file_content = file.read()
                            encrypted_files[file_name] = file_content
                            entropy, chi = calc_X2_entropy(0, file_path)
                            max_wavelet = wavelet_convolution(file_path, 0, 256, 16)
                            print(f"Файл относится к известным сигнатурам")
                            print(f"Имя файла: {file_name}")
                            print(f"Расширение: {os.path.splitext(file_name)[-1]}")
                            print(f"Размер файла: {os.path.getsize(file_path)} байт")
                            print(f"Заголовок: {file_signature}")
                            print(f"Критерий Пирсона: {chi}")
                            print(f"Max Вейвлет-коэффициент: {max_wavelet}")
                            print("=" * 50)
            else:
                if (os.path.getsize(file_path) > 299008):
                    entropy, chi = calc_X2_entropy(0, file_path)
                    if (entropy != 0 and chi != 0):
                        print(f"Имя файла: {file_name}")
                        print(f"Расширение: {os.path.splitext(file_name)[-1]}")
                        print(f"Размер файла: {os.path.getsize(file_path)} байт")
                        print(f"Заголовок: {file_signature}")
                        entropy, chi = calc_X2_entropy(0, file_path)
                        max_wavelet = wavelet_convolution(file_path, 0, 256, 16)
                        print(f"Энтропия: {entropy}")
                        print(f"Критерий Пирсона: {chi}")
                        print(f"Max Вейвлет-коэффициент: {max_wavelet}")
                        print("=" * 50)

    return encrypted_files

def input_with_hint(prompt, hint):
    def hook():
        readline.insert_text(hint)
        readline.redisplay()
    readline.set_pre_input_hook(hook)
    try:
        return input(prompt)
    finally:
        readline.set_pre_input_hook()

if __name__ == "__main__":
    while True:
        directory_to_check = input_with_hint("Введите директорию для поиска: (для получения справки введите help)\n", "/home/ubuntu/")
        if directory_to_check.lower() == "help":
            print("Программа предназначена для поиска криптоконтейнеров в системах с ОС Linux. Для поиска криптоконтейнеров введите директорию")
            continue
        if os.path.isdir(directory_to_check):
            print("=" * 50)
            encrypted_files_dict = collect_encrypted_files(directory_to_check)
        print("\nХотите продолжить поиск? (да/нет)")
        answer = input().lower()
        if (answer != "да") or (answer != "lf"):
            break