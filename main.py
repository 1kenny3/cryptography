import os
import json
import base64
from aiogram import Bot, Dispatcher, executor, types
from aiogram.types import InputFile
from aiogram.dispatcher.filters import Text
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

API_TOKEN = ''

bot = Bot(token=API_TOKEN)
dp = Dispatcher(bot)

# Генерация пары ключей RSA
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()

# Сохранение закрытого и открытого ключей в файлы
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('private_key.pem', 'wb') as f:
    f.write(private_key_pem)

with open('public_key.pem', 'wb') as f:
    f.write(public_key_pem)

# Генерация и шифрование ключа DES
des_key = os.urandom(24)
encrypted_des_key = public_key.encrypt(
    des_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Функции для дополнения текста до кратности блока DES
def pad_des(data):
    padder = sym_padding.PKCS7(algorithms.TripleDES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad_des(data):
    unpadder = sym_padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

# Инициализация шифрования DES
def create_des_cipher(key, iv):
    return Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())

# Хранилище для отслеживания ID сообщений
message_ids = []

@dp.message_handler(commands=['start'])
async def send_welcome(message: types.Message):
    msg = await message.answer("Привет! Отправь мне сообщение, и я зашифрую его.")
    message_ids.append(msg.message_id)

@dp.message_handler(commands=['delete'])
async def delete_file(message: types.Message):
    try:
        if os.path.exists('encrypted_message.json'):
            os.remove('encrypted_message.json')
            await message.answer("Файл encrypted_message.json успешно удалён.")
        else:
            await message.answer("Файл encrypted_message.json не найден.")
        
        # Удаление всех сообщений в чате
        for msg_id in message_ids:
            try:
                await bot.delete_message(message.chat.id, msg_id)
            except:
                pass  # Игнорировать ошибки при удалении
        message_ids.clear()
    except Exception as e:
        await message.answer(f"Произошла ошибка при удалении файла: {str(e)}")

@dp.message_handler(Text(equals='decrypt', ignore_case=True))
async def decrypt_message_handler(message: types.Message):
    msg = await message.answer("Отправь мне файл с зашифрованным сообщением для расшифровки.")
    message_ids.append(msg.message_id)

@dp.message_handler(content_types=['text'])
async def encrypt_message_handler(message: types.Message):
    try:
        text = message.text.encode('utf-8')
        
        padded_text = pad_des(text)
        
        iv = os.urandom(8)
        des_cipher = create_des_cipher(des_key, iv)
        encryptor = des_cipher.encryptor()
        encrypted_text = encryptor.update(padded_text) + encryptor.finalize()

        encrypted_message = {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'message': base64.b64encode(encrypted_text).decode('utf-8')
        }

        with open('encrypted_message.json', 'w') as f:
            json.dump(encrypted_message, f)

        msg = await message.reply("Сообщение зашифровано и сохранено.", reply=False)
        message_ids.append(msg.message_id)
        
        doc_msg = await bot.send_document(message.chat.id, InputFile('encrypted_message.json'))
        message_ids.append(doc_msg.message_id)
    except Exception as e:
        msg = await message.reply(f"Произошла ошибка: {str(e)}")
        message_ids.append(msg.message_id)

@dp.message_handler(content_types=['document'])
async def handle_docs(message: types.Message):
    try:
        document_id = message.document.file_id
        file_info = await bot.get_file(document_id)
        downloaded_file = await bot.download_file(file_info.file_path)

        with open('encrypted_message.json', 'wb') as new_file:
            new_file.write(downloaded_file.read())

        with open('encrypted_message.json', 'r') as f:
            data = json.load(f)
            iv = base64.b64decode(data['iv'])
            encrypted_text = base64.b64decode(data['message'])

        des_cipher = create_des_cipher(des_key, iv)
        decryptor = des_cipher.decryptor()
        padded_text = decryptor.update(encrypted_text) + decryptor.finalize()
        decrypted_text = unpad_des(padded_text)

        msg = await message.reply(f"Расшифрованное сообщение: {decrypted_text.decode('utf-8')}")
        message_ids.append(msg.message_id)
    except Exception as e:
        msg = await message.reply(f"Произошла ошибка: {str(e)}")
        message_ids.append(msg.message_id)

if __name__ == '__main__':
    executor.start_polling(dp, skip_updates=True)
