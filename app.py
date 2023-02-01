import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from flask import Flask, jsonify, request
import requests
from datetime import datetime, timedelta
from timeFromFirstDay import timeFromFirstDay
from findCommonSubstring import find_common_substring
from loadTree import load_tree
from getPasswd import getPassword
from binaryTree import BinaryTree, Node
from flask_cors import CORS



##############################
def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = key[:16]  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    #print("data->", base64.b64encode(data).decode("latin-1"))
    return base64.b64encode(data).decode("latin-1") if encode else data

def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = key[:16]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding


def getHash(_inputer_from):
    # _inputer_from = request.args["Bin"]
    inputer = _inputer_from
    tree = load_tree("test2.bin")
    #print(tree.search(inputer))
    treeSearch = tree.search(inputer)
    #print("Inside getHash function: ", treeSearch)
    return treeSearch

def listPasswd():
    inputer = timeFromFirstDay()
    listBins = []
    _listPasswd = []

    for i in range(0,len(inputer)):
        listBins.append(inputer[0:i])
        #print("Inside listpasswd 2: ", listBins)
    for j in range(0, len(listBins)):
        _listPasswd.append(getHash(listBins[j]))
    return _listPasswd

    



app = Flask(__name__)
CORS(app)


@app.route('/')
# ‘/’ URL is bound with hello_world() function.
def hello_world():
    return 'Hello World'


@app.route('/input_hash', methods=['GET'])
def inputHash():
    #taking inputs
    _inputer_from = request.args["From"]
    _inputer_to = request.args["To"]

    #finding common substring
    inputer = find_common_substring(_inputer_from, _inputer_to)

    tree = load_tree("test2.bin")
    #print(tree.search(inputer))
    return jsonify(tree.search(inputer))


@app.route('/encrypting', methods=["GET"])
def encryption():
    import urllib.parse
    

    _from_date = request.args["From_date"]
    _from_hour = request.args["From_hour"]
    _to_date = request.args["To_date"]
    _to_hour = request.args["To_hour"]
    _data = request.args["Data"]
    _passwd = getPassword(_from_date,_from_hour,_to_date,_to_hour)
    passwd = bytes(_passwd, "ascii")
    data = bytes(_data,"ascii")
    my_password = passwd
    my_data = data
    safe_string = urllib.parse.quote_plus(encrypt(my_password, my_data))
    #print(safe_string)
    jsoning = {
        "ciphertext": safe_string,
        "password": _passwd
    }
    return jsonify(jsoning)


@app.route('/testin2')
def testing2():
    return 'You are in testing 2'

@app.route('/testing', methods=['GET'])
def testing():
    return "You are in Testing"

@app.route('/decrypting', methods=["GET"])
def decryption():
    _cipher = request.args["cipher"]
    _list_of_pwd = listPasswd()
    passwd = []
    message = ""
    for j in range(0,len(_list_of_pwd)):
        _passwd = _list_of_pwd[j]
        passwd.append((bytes(str(_passwd), "ascii")))
    for k in range(0, len(passwd)):
        try:
            message = str(decrypt(passwd[k], _cipher).decode())
        except:
            pass
    responsing  = {
        "Message": message
    }
    return jsonify(responsing)
if __name__ == "__main__":
    from waitress import serve
    serve(app, host = '0.0.0.0',port = 6117)