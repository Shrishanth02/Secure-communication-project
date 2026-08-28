from django.shortcuts import render
from django.template import RequestContext
from django.contrib import messages
from django.http import HttpResponse
import os
from django.core.files.storage import FileSystemStorage
import pymysql
import codecs
import random
import pyaes, pbkdf2, binascii, os, secrets
import base64
import hashlib
import datetime

global uname, filename, shared_key

space0 = "​"
space1 = "‌"

def hide(text,message):
    message = "".join(format(ord(i),"08b") for i in str(message))
    midpoint = int((len(text)/2)//1)
    result = ""
    for i in list(str(message)):
        result += space0 if i == "0" else space1 if i == "1" else ""
    return text[:midpoint]+result+text[midpoint:]

def show(text):
    result = ""
    for i in list(str(text)):
        if i == space0:
            result += "0"
        elif i == space1:
            result += "1"
    result = "".join([chr(int(result[i:i+8],2)) for i in range(0,len(result),8)])
    if result == "":
        result = None
    return result

def getDiffieKey():#function to get common secret key between two users as shared1 and shared2
    P = 23
    G = 9
    x1 = random.randint(10,100)
    x2 = random.randint(10,100)
    y1, y2 = pow(G, x1) % P, pow(G, x2) % P
    share1, share2 = pow(y2, x1) % P, pow(y1, x2) % P
    return share1

def getKey(diffie_key): #generating AES key based on Diffie common secret shared key
    password = "s3cr3t*c0d3"
    passwordSalt = str(diffie_key)#get AES key using diffie
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    return key

def encrypt(plaintext, key): #AES data encryption
    aes = pyaes.AESModeOfOperationCTR(getKey(key), pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    ciphertext = aes.encrypt(plaintext)
    return ciphertext

def decrypt(enc, key): #AES data decryption
    aes = pyaes.AESModeOfOperationCTR(getKey(key), pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    decrypted = aes.decrypt(enc)
    return decrypted

def UploadAction(request):
    if request.method == 'POST':
        global uname
        file_data = request.FILES['t1'].read()#read data from uploaded file
        file_name = request.FILES['t1'].name #get the name of the file
        file_data = codecs.decode(file_data)#convert binary data to string
        diffie_key = getDiffieKey()#get Diffie key
        encrypted_data = encrypt(file_data, diffie_key)#call AES encrypt function to encrypt given file data using diffie key
        encrypted_data = base64.b64encode(encrypted_data).decode()#convert AES binary data to string to hide diffie key so receiver or file downloader can extract
        hidden = hide(encrypted_data, diffie_key)#now hide diffie secret key on encrypted data
        with open('SecureApp/static/files/'+file_name, "wb") as file:
            file.write(hidden.encode())
        file.close()
        hash_object = hashlib.sha1(hidden.encode())
        hashcode = hash_object.hexdigest()
        output = file_name+' encrypted using Diffie shared key & AES : '+str(diffie_key)+"<br/>Diffie Key hide inside encrypted File"
        output += "<br/>Data Integrity will check with Hascode = "+hashcode
        now = datetime.datetime.now()
        current_time = now.strftime("%Y-%m-%d %H:%M:%S")
        db_connection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'secureapp',charset='utf8')
        db_cursor = db_connection.cursor()
        student_sql_query = "INSERT INTO files(owner, filename, hashcode, upload_date) VALUES('"+uname+"','"+file_name+"','"+hashcode+"','"+str(current_time)+"')"
        db_cursor.execute(student_sql_query)
        db_connection.commit()
        context= {'data':output}
        return render(request, 'UploadFile.html', context)

def DownloadFileAction(request):
    if request.method == 'GET':
        global uname
        filename = request.GET['t1']
        key = request.GET['t2']
        with open('SecureApp/static/files/'+filename, "rb") as file:
            filedata = file.read()
        file.close()
        filedata = base64.b64decode(filedata)
        dec = decrypt(filedata, key)
        response = HttpResponse(dec, content_type="application/octet-stream")
        response['Content-Disposition'] = "attachment; filename=%s" % filename
        return response

def getHashcode(filename):
    hashcode = None
    con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'secureapp',charset='utf8')
    with con:
        cur = con.cursor()
        cur.execute("select hashcode FROM files where filename='"+filename+"'")
        rows = cur.fetchall()
        for row in rows:
            hashcode = row[0]
            break
    return hashcode

def FileIntegrityAction(request):
    if request.method == 'GET':
        global uname
        filename = request.GET['t1']
        hashcode = request.GET['t2']
        with open('SecureApp/static/files/'+filename, "rb") as file:
            filedata = file.read()
        file.close()
        hash_object = hashlib.sha1(filedata)
        generated_hashcode = hash_object.hexdigest()
        output = "File Integrity Failed. Data Changed"
        if hashcode == generated_hashcode:
            output = "File Integrity Successful. No Data Changed"
        context= {'data':output}        
        return render(request, 'UserScreen.html', context)    

def FileIntegrity(request):
    if request.method == 'GET':
        global uname
        output = '<table border=1 align=center width=100%>'
        font = '<font size="" color="black">'
        arr = ['Filename', 'Extracted Hidden Diffie Shared Key', 'File Integrity Hashcode', 'Check File Integrity']
        output += "<tr>"
        for i in range(len(arr)):
            output += "<th>"+font+arr[i]+"</th>"
        output += "</tr>"
        path = "SecureApp/static/files"
        for root, dirs, directory in os.walk(path):
            for j in range(len(directory)):
                with open(root+"/"+directory[j], "rb") as file:
                    hidden = file.read()
                file.close()
                hashcode = getHashcode(directory[j])
                hashcode_display = hashcode if hashcode is not None else "No hashcode available"
                showing = show(hidden.decode())
                output += "<tr><td>"+font+directory[j]+"</td>"
                output += "<td>"+font+str(showing)+str(random.randint(1000,100000))+"</td>"
                output += "<td>"+font+hashcode_display+"</td>"
                if hashcode is not None:
                    output += '<td><a href="FileIntegrityAction?t1='+directory[j]+'&t2='+str(hashcode)+'">'+font+'Click Here</a></td></tr>'
                else:
                    output += '<td>'+font+'No hashcode to check integrity</td></tr>'
        context = {'data': output}
        return render(request, 'UserScreen.html', context)



def DownloadFile(request):
    if request.method == 'GET':
        global uname
        output = '<table border=1 align=center width=100%>'
        font = '<font size="" color="black">'
        arr = ['Filename', 'Extracted Hidden Diffie Shared Key', 'File Integrity Hashcode', 'Download']
        output += "<tr>"
        for i in range(len(arr)):
            output += "<th>"+font+arr[i]+"</th>"
        output += "</tr>"
        path = "SecureApp/static/files"
        for root, dirs, directory in os.walk(path):
            for j in range(len(directory)):
                with open(root+"/"+directory[j], "rb") as file:
                    hidden = file.read()
                file.close()
                showing = show(hidden.decode())
                hashcode = getHashcode(directory[j])
                hashcode_display = hashcode if hashcode is not None else "No hashcode available"
                output += "<tr><td>"+font+directory[j]+"</td>"
                output += "<td>"+font+str(showing)+str(random.randint(1000,100000))+"</td>"
                output += "<td>"+font+hashcode_display+"</td>"
                if showing is not None:
                    output += '<td><a href="DownloadFileAction?t1='+directory[j]+'&t2='+str(showing)+'">'+font+'Click Here</a></td></tr>'
                else:
                    output += '<td>'+font+'Invalid Key</td></tr>'
        context = {'data': output}
        return render(request, 'UserScreen.html', context)
    

def UploadFile(request):
    if request.method == 'GET':
       return render(request, 'UploadFile.html', {})  

def UserLogin(request):
    if request.method == 'GET':
       return render(request, 'UserLogin.html', {})  

def index(request):
    if request.method == 'GET':
       return render(request, 'index.html', {})

def Signup(request):
    if request.method == 'GET':
       return render(request, 'Signup.html', {})

def UserLoginAction(request):
    global uname
    if request.method == 'POST':
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        index = 0
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'secureapp',charset='utf8')
        with con:
            cur = con.cursor()
            cur.execute("select username,password FROM signup")
            rows = cur.fetchall()
            for row in rows:
                if row[0] == username and password == row[1]:
                    uname = username
                    index = 1
                    break		
        if index == 1:
            context= {'data':'welcome '+uname}
            return render(request, 'UserScreen.html', context)
        else:
            context= {'data':'login failed'}
            return render(request, 'UserLogin.html', context)        

def SignupAction(request):
    if request.method == 'POST':
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        contact = request.POST.get('t3', False)
        gender = request.POST.get('t4', False)
        email = request.POST.get('t5', False)
        address = request.POST.get('t6', False)
        output = "none"
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'secureapp',charset='utf8')
        with con:
            cur = con.cursor()
            cur.execute("select username FROM signup")
            rows = cur.fetchall()
            for row in rows:
                if row[0] == username:
                    output = username+" Username already exists"
                    break
        if output == 'none':
            db_connection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'secureapp',charset='utf8')
            db_cursor = db_connection.cursor()
            student_sql_query = "INSERT INTO signup(username,password,contact_no,gender,email,address) VALUES('"+username+"','"+password+"','"+contact+"','"+gender+"','"+email+"','"+address+"')"
            db_cursor.execute(student_sql_query)
            db_connection.commit()
            print(db_cursor.rowcount, "Record Inserted")
            if db_cursor.rowcount == 1:
                output = 'Signup Process Completed'
        context= {'data':output}
        return render(request, 'Signup.html', context)
      


