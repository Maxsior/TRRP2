import pika
import sqlite3
import socket
import json
import zlib
import math
import hashlib
import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.Random import get_random_bytes


des_key = get_random_bytes(8)
des_cipher = DES.new(des_key, DES.MODE_ECB)
print(f'Симметричный ключ: {SHA256.new(des_key).hexdigest()}')

HOST = os.getenv('HOST') or 'localhost'
PORT = os.getenv('PORT') or 9999

BUFFER_SIZE = 1024
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((HOST, PORT))
    sock.sendall(b'PKEY')
    data = sock.recv(BUFFER_SIZE)
    print(f'Хэш полученного публичного ключа: {SHA256.new(data=data).hexdigest()}')
    rsa_publickey = RSA.import_key(data)
    rsa_cipher = PKCS1_OAEP.new(rsa_publickey)
    des_key_encrypted = rsa_cipher.encrypt(des_key)
    print(f'Хэш зашифрованного симметричного ключа: {SHA256.new(data=des_key_encrypted).hexdigest()}')
    sock.sendall(des_key_encrypted)
    buid = sock.recv(BUFFER_SIZE)
    print("Идентификатор пользователя: ", buid)


def dict_factory(cursor, row):
    return {
        col[0]: row[idx]
        for idx, col in enumerate(cursor.description)
    }


conn = sqlite3.connect('vet.sqlite')
conn.row_factory = dict_factory
cursor = conn.cursor()

connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
channel = connection.channel()
channel.queue_declare(queue='vet')

cursor.execute("SELECT * FROM checks LIMIT 1")
row = cursor.fetchone()
print('Тип столбцов:')
for k, v in row.items():
    print(k, ':', type(v))

count = 0
for row in cursor.execute("SELECT * FROM checks"):
    count += 1
    row_json = json.dumps(row).encode('utf8')
    row_compressed = zlib.compress(row_json, level=9)
    row_padded_len = math.ceil(len(row_compressed) / 8) * 8
    row_padded = row_compressed.ljust(row_padded_len, b' ')
    row_encrypted = des_cipher.encrypt(row_padded)

    hash_object = hashlib.md5(row_json)
    print('Хэш до шифрования', hash_object.hexdigest())
    hash_object.update(row_encrypted)
    print('Хэш после шифрования', hash_object.hexdigest())

    print('Длина до/после сжатия:', len(row_json), '->', len(row_encrypted))

    msg = buid + row_encrypted
    channel.basic_publish(exchange='', routing_key='vet', body=msg)

print('Обработано записей: ', count)

connection.close()


