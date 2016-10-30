from array import*
import numpy as np
from ClassProcess import*
import string

print "**********************************************\n"
print "---------DES decryption test------------------\n"
print "-----COT5930 Cryptography  -- Assignment2 ----\n"
print "**********************************************\n\n"


#Ask input message to do the encryption
# and check if encrypt text is hexadecimal, lenght = 16?
while True:
    En_text = raw_input ("Please enter the encrypted text (16xn hexa) to decrypt: ")
    if len(En_text)%16<>0:
        print "Encrypted text must be 16xn hexadecimal characters\n"   
        continue
    elif (all(c in string.hexdigits for c in En_text)==False):
        print "Encrypted text must be hexadecimal \n"
        continue

    else:
        
        break
nBlock = len(En_text)/16 #get the number of block yi

print "This is the encrypted text that you want to decrypt: \n"
print "            " + En_text +"\n"

Decrypt_Des1 = KeyProcess() #Call the KeyProcess class 
Hex_Bin = Decrypt_Des1.convert(En_text,2)
En_input=[]
En_Hex=''.join('{:08b}'.format(int(x, 16)) for x in Hex_Bin)
for i in En_Hex:
    En_input.append(int(i))


#Array En_input is the encrypted text in binary number
#Finish getting the encrypted text
#Now ask for the key to decrypt

while True:
    K_text = raw_input ("Please enter a key to encrypt: ")
    if len(K_text) <3:
        print "Your key is too short, if you enter a wrong key, you'll get a wrong message\n"   
        continue
    elif len(K_text) >= 9:
        print "Your key is too long, should be 8 or shorter\n"   
        continue
    else:
        
        break

print"This is the key that you enter - if you enter a wrong key, you will get a wrong message:  " 
print "                       " + K_text +"\n"

KeyIn=[]
binKey = ''.join(format(ord(x), 'b').zfill(8) for x in K_text)
for i in binKey:
    KeyIn.append(int(i))

#In case that the length of the key is less than 64 bits => add '1' to make up 64 bit
if len(KeyIn)<64:
    for j in range(0,(64-len(KeyIn))):
        KeyIn.append(1)



  ##################################
  # Process the key, create 16 sub keys
  ################################## 
Key_Decrypt = KeyProcess() #Call the KeyProcess class
#Call function Key generator to create 16 sub keys
KeyA = Key_Decrypt.KeyGenerator(KeyIn) #The array KeyA contain 16 subkeys"
#Finished generating 16 sub keys

''' 
#################################
Now process the data. This step will use some functions in the key_process class
#################################
'''

Data_Decrypt = DataProcess() #Call the Data Process class 
#Return the result of decryption

IV = Key_Decrypt.ReadFile('TableIV.txt')

En_TextIn = [[0 for x in range(64)] for y in range(nBlock)]
String_Return ='' #This is the final decryption text

for k in range (0,nBlock):
    En_TextIn[k] = En_input[k*64:(k+1)*64]

for ii in range (0,nBlock):
    
    if ii ==0: 
        ArrayText,EncryptText = Data_Decrypt.Decrypt_text(En_TextIn[ii],KeyA)
        #XOR plain text with the Initialize Vector
        TextOut1 = np.bitwise_xor(ArrayText,IV)
        
        KK = ''.join(format(x, 'b') for x in TextOut1)
        bin_str = Key_Decrypt.convert(KK,8)
        Decrypt=''.join(chr(int(b, 2)) for b in bin_str)
        String_Return = Decrypt
    else:
        ArrayText,EncryptText = Data_Decrypt.Decrypt_text(En_TextIn[ii],KeyA)
        #XOR plain text with the Initialize Vector
        TextOut1 = np.bitwise_xor(ArrayText,En_TextIn[ii-1])
        KK = ''.join(format(x, 'b') for x in TextOut1)
        bin_str = Key_Decrypt.convert(KK,8)
        Decrypt=''.join(chr(int(b, 2)) for b in bin_str)
        String_Return = String_Return + Decrypt

    

print "This is the message text after processing decryption \n"
print "                 " + String_Return
print "\n ****************  Finish  ******************************\n"
