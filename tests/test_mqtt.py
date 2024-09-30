""" Tests for mqtt """

import paho.mqtt.client as mqtt
from pymccool.logging import Logger, LoggerKwargs

logger = Logger(LoggerKwargs(app_name="TEST"))

def test_sanity():
    """ Should always pass """
    assert True

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, reason_code, properties):
    print(f"Connected with result code {reason_code}")
    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("TEST/#", qos=1)

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic+" "+str(msg.payload))

def test_mqtt():
    mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    mqttc.on_connect = on_connect
    mqttc.on_message = on_message
    mqttc.subscribe("sensors/+/temperature/+", qos=1)

    logger.info("Connecting to MQTT")
    error_code = mqttc.connect("127.0.0.1", 1883, 60)
    mqttc.enable_logger(logger)
    mqttc.user_data_set("Hello, world!")
    logger.info(f"Connected with error code {error_code}")
    
    logger.info("Publishing messages...")
    mqttc.publish("sensors/fl13/temperature/AC", "25.0")
    mqttc.publish("sensors/fl10/temperature/boiler", "25.1")
    mqttc.publish("sensors/fl10/temperature/heater", "25.2")

    # Blocking call that processes network traffic, dispatches callbacks and
    # handles reconnecting.
    # Other loop*() functions are available that give a threaded interface and a
    # manual interface.
    logger.info("Looping")
    error_code = mqttc.loop_forever()
    logger.info(f"Looped with error code {error_code}")
    logger.info(f"Received the following message: {mqttc.user_data_get()}")
    
