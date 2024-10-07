
#!/usr/bin/python
import requests
import json
from typing import Union, List, Dict, TypeAlias
from rich import print
import paho.mqtt.client as mqtt
from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pathlib import Path
import time

from pymccool.logging import Logger, LoggerKwargs

Json: TypeAlias = dict[str, "JSON"] | list["JSON"] | str | int | float | bool | None

logger = Logger(LoggerKwargs(app_name="TEST"))

MQTT_ENDPOINT = "mqtt.nrfcloud.com"
MQTT_TOPIC_PREFIX = "prod/be634dca-20f5-43e8-bca0-c34c1642fd6c"
HOSTNAME = "FWA002539"
API_KEY = "95c502db2a055a59d95c8a517697ed1fc828c6c3"

# All connections to the AWS IoT MQTT broker must use Mutual TLS on port 8883.  
# This means that devices using MQTT must have an X.509 device certificate and be onboarded to nRF Cloud.


from datetime import datetime, timedelta
import ipaddress

def generate_selfsigned_cert(hostname, ip_addresses=None, key=None):
    """Generates self signed certificate for a hostname, and optional IP addresses."""

    
    # Generate our key
    if key is None:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
    
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    ])
 
    # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.    
    alt_names = [x509.DNSName(hostname)]
    
    # allow addressing by IP, for when you don't have real DNS (common in most testing scenarios 
    if ip_addresses:
        for addr in ip_addresses:
            # openssl wants DNSnames for ips...
            alt_names.append(x509.DNSName(addr))
            # ... whereas golang's crypto/tls is stricter, and needs IPAddresses
            # note: older versions of cryptography do not understand ip_address objects
            alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))
    
    san = x509.SubjectAlternativeName(alt_names)
    
    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10*365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, key_pem

class nRFCloud:
    API_HOST = "https://api.nrfcloud.com"
    def __init__(self):
        # Write the keys if they don't exist
        if not Path("cert.pem").exists() or not Path("key.pem").exists():
            logger.info("Could not find cert.pem or key.pem, writing new ones")
            cert, key = generate_selfsigned_cert("FWA002539")
            logger.info(cert)
            logger.info(key)
            with open("cert.pem", "wb") as f:
                f.write(cert)
            with open("key.pem", "wb") as f:
                f.write(key)
        else:
            logger.info("Found cert.pem and key.pem, skipping write")

    def endpoint_get(self, endpoint, data: Json) -> Json:
        headers = {'Authorization': f'Bearer {API_KEY}',
                   'Content-Type': 'application/json',
                   'Accept': '*/*'}
        response = requests.get(f"{self.API_HOST}/{endpoint}", data=data, headers=headers, timeout=10)
        return response.text
    
    def endpoint_post(self, endpoint, data: Json) -> Json:
        #headers = {'Accept-Encoding': 'UTF-8', 'Content-Type': 'application/json', 'Accept': '*/*', 'username': 'user', 'password': 'pwd'}
        headers = {'Authorization': f'Bearer {API_KEY}',
                   'Content-Type': 'application/json',
                   'Accept': '*/*'}
        response = requests.post(f"{self.API_HOST}/{endpoint}", data=data, headers=headers, timeout=10)
        return response.text
    
    def onboard_device(self, cert, key):

        logger.info(f"Onboarding device {HOSTNAME}")

        with open(cert, "r") as f:
            cert = f.read()
            cert = json.dumps({"certificate": cert})

        logger.info(cert)

        response = self.endpoint_post(f"v1/devices/{HOSTNAME}", data=cert)

        logger.info(f"Response code: {response.status_code}")
        logger.info(response)


def test_cloud_schema():
    nrf = nRFCloud()
    response = nrf.endpoint_get("v1/openapi.json")
    logger.pretty(logger.INFO, response)



def test_onboard_device():
    nrf = nRFCloud()
    nrf.onboard_device("cert.pem", "key.pem")

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, reason_code, properties):
    print(f"Connected with result code {reason_code}")
    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("TEST/#", qos=1)

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic+" "+str(msg.payload))

def test_mqtt_publish():
    mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    mqttc.on_connect = on_connect
    mqttc.on_message = on_message


    logger.info("Connecting to MQTT")
    mqttc.tls_set(ca_certs="./AmazonRootCA1.pem", certfile="cert.pem", keyfile="key.pem")
    error_code = mqttc.connect(MQTT_ENDPOINT, 8883, 60)
    mqttc.enable_logger(logger)
    logger.info(f"Connected with error code {error_code}")
    

    logger.info("Looping")
    error_code = mqttc.loop_start()

    logger.info("Subscribing")
    topic = f"{MQTT_TOPIC_PREFIX}/m/d/{HOSTNAME}/sensor/temperature/room2"
    mqttc.subscribe(topic, qos=1)

    logger.info("Publishing messages...")
    
    message = json.dumps({"temp": 59, "units": "F", "timestamp": "2024-10-04T12:00:00Z"})
    message_info = mqttc.publish(topic, "25.0")
    time.sleep(2)
    mqttc.loop_stop()
    logger.info(f"Message info: {message_info}")

def test_mqtt_get_messages():
    topic = f"{MQTT_TOPIC_PREFIX}/m/d/{HOSTNAME}/sensor/temperature/room2"
    nrf = nRFCloud()
    response = nrf.endpoint_get("messages", data=json.dumps({}))
    logger.pretty(logger.INFO, response)
