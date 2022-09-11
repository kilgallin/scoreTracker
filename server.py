import cherrypy
from cherrypy.process import servers
from cherrypy.lib.static import serve_file
import os
import hashlib
import binascii
import json
import sys

#the set of user files and passwords are encrypted with this application and 
#stored in a special file in the data directory; userpass is the passphrase/key
#to be used for this file and is loaded from a text document
userpass=''

#open a file and return its contents
def getFile(filename,mode="r"):
  f = open(filename,mode)
  contents = f.read()
  f.close()
  return contents

#symmetric-key algorithm for encryption and decryption, based on md5
def crypt(text, passphrase):
  m = hashlib.md5()
  pad = ""
  last = ""
  text = binascii.hexlify(text)
  while(len(pad) < len(text)):
    encoded = last+passphrase
    m.update(encoded.encode('utf-8'))
    last = m.hexdigest()
    pad = pad + last
  pad = pad[0:len(text)]
  result = ""
  while(len(text) > 0):
    tc = text[0]
    text = text[1:len(text)]
    pc = pad[0]
    pad = pad[1:len(pad)]
    newint = int(str(tc),16) ^ int(str(pc),16)
    newchar = str(hex(newint))[2]
    result = result + newchar
  return binascii.unhexlify(result)

#Backend web interface
class Server(object):
  #constructor; only needs to load the passphrase
  def __init__(self):
    global userpass
    userpass = getFile('passphrase.txt')
    return

  #program entry point for a client application; loads a web interface providing
  #access to the remaining program
  def index(self):
    scores = json.loads(getFile('scores.txt'))
    names = scores.keys()
    ans = "<html><body align='center'><table align='center'>"
    for name in names:
        name2 = name
        if name == "Jeff":
            name2 = "<marquee>Jeff</marquee>"
        ans = ans + "<tr><td>" + name2 +"</td>"
        tScore = 0
        for score in scores[name]:
            tScore += score
            ans += "<td align='center'>" + str(score) + "</td>"
        ans += "<td style='color:green'><b>" + str(tScore) + "</b><td>"
    return ans
  index.exposed = True

  #attempts to load an encrypted file, decrypt it with the provided key, and
  #return the plaintext result. Returns garbage for an incorrect passphrase.
  def read(self, username, password, filename, passphrase):
    global userpass
    userdict = json.loads(crypt(getFile('data/users','rb+'),userpass))
    if username not in userdict.keys() or password not in userdict[username]:
        return "Access attempt failed"
    userdict = json.loads(crypt(getFile('data/targets','rb+'),userpass))
    return userdict[username]
  read.exposed = True

#program entry point; launches a "Server" object instance on port 8766,
#listening for https traffic
if __name__ == '__main__':
    cherrypy.server.socket_host = '0.0.0.0'
    cherrypy.server.socket_port = 8225
    cherrypy.quickstart(Server())