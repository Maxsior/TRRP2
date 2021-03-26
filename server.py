import pika
import sys
import socketserver
import threading
import zlib
import uuid
import json
import pymysql
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import config
import logging
logging.basicConfig(stream=sys.stdout)


keys = {}


def start_queue_server():
    logger = logging.getLogger('queue_server')
    logger.setLevel(logging.DEBUG)
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=config.host))
    channel = connection.channel()
    channel.queue_declare(queue='vet')

    def callback(ch, method, properties, body):
        buid, row_encrypted = body[:16], body[16:]

        des_cipher = DES.new(keys[buid], DES.MODE_ECB)
        row_compressed = des_cipher.decrypt(row_encrypted).lstrip(b' ')
        row_json = zlib.decompress(row_compressed)
        row = json.loads(row_json)
        logger.info(f'received {row}')

        conn = pymysql.connect(**config.db)
        cursor = conn.cursor()
        cursor.execute("""REPLACE INTO People (Name) VALUES (%s)""", row['Owner'])
        owner_id = cursor.lastrowid
        cursor.execute("""REPLACE INTO Services (Title, Price) VALUES (%s, %s)""", (row['Service'], row['Price']))
        service_id = cursor.lastrowid
        cursor.execute("""REPLACE INTO Pets (Name, Owner) VALUES (%s, %s)""", (row['Pet'], owner_id))
        pet_id = cursor.lastrowid
        cursor.execute("""REPLACE INTO Appointments (Time, Pet) VALUES (%s, %s)""", (row['Time'], pet_id))
        appointment_id = cursor.lastrowid
        cursor.execute("""REPLACE INTO Checks (Appointment, Service) VALUES (%s, %s)""", (appointment_id, service_id))
        conn.commit()
        conn.close()

    channel.basic_consume(queue='vet', on_message_callback=callback, auto_ack=True)

    logger.info('Queue server is waiting for messages')
    channel.start_consuming()


def start_socket_server():
    addr = config.addr
    logger = logging.getLogger('socket_server')
    logger.setLevel(logging.DEBUG)

    privatekey = RSA.generate(1024)
    publickey = privatekey.publickey()
    publickey_bytes = publickey.export_key()

    class Handler(socketserver.BaseRequestHandler):
        BUFFER_SIZE = 1024

        def handle(self):
            cmd = self.request.recv(self.BUFFER_SIZE)
            if cmd == b'PKEY':
                self.request.sendall(publickey_bytes)
                des_encrypted = self.request.recv(self.BUFFER_SIZE)
                rsa_cipher = PKCS1_OAEP.new(privatekey)
                des_key = rsa_cipher.decrypt(des_encrypted)
                buid = uuid.uuid4().bytes
                keys[buid] = des_key
                self.request.sendall(buid)

    with socketserver.TCPServer(addr, Handler) as server:
        logger.info(f'Socket server listen on {addr}')
        server.serve_forever()


if __name__ == '__main__':
    socket_thread = threading.Thread(target=start_socket_server)
    queue_thread = threading.Thread(target=start_queue_server)
    socket_thread.start()
    queue_thread.start()
