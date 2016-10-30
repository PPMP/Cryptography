from array import*
import numpy as np
from ClassProcess import*
import string

print "**********************************************\n"
print "---------DES encryption test------------------\n"
print "-----COT5930 Cryptography  -- Assignment2 ----\n"
print "-----By Deepthi + Patorn + Khoa----------------\n"
print "**********************************************\n\n"

#Ask input message to do the encryption

while True:
    ptext = raw_input ("Please enter the plain text (8xn characters) to encrypt: ")
    if (len(ptext))%8 <>0:
        print "Plain text must be 8 characters\n"   
        continue
    else:
        
        break
#Get the number of block text (each block 8 character or 64 bits)
nBlock = len(ptext)/8

print "This is the message that you want to encrypt: \n"
print "            " + ptext +"\n"

TextIn=[]
binaryK = ''.join(format(ord(x), 'b').zfill(8) for x in ptext)
for i in binaryK:
    TextIn.append(int(i))


###Finish gather data and convert to arrays bit#############

#########################################
#Now ask for the key to encrypt

while True:
    K_text = raw_input ("Please enter a key to encrypt - Don't forget your key: ")
    if len(K_text) <3:
        print "Your key is too short\n"   
        continue
    elif len(K_text) >= 9:
        print "Your key is too long characters\n"   
        continue
    else:
        
        break

print"This is the key that you enter:  " + K_text +"\n"

KeyIn=[]
binKey = ''.join(format(ord(x), 'b').zfill(8) for x in K_text)
for i in binKey:
    KeyIn.append(int(i))

#In case that the length of the key is less than 64 bits => add '1' to make up 64 bit
if len(KeyIn)<64:
    for j in range(0,(64-len(KeyIn))):
        KeyIn.append(1)
#Finish getting the key

Key_Processing = KeyProcess() #Call the KeyProcess class 
#Call function Key generator to create 16 sub keys
KeyA = Key_Processing.KeyGenerator(KeyIn) #The array KeyA contain 16 subkeys"
#Finished generating 16 sub keys

##################################
#Read the value of Initialize Vector IV
IV =Key_Processing.ReadFile('TableIV.txt')

''' 
#################################
Now process the data. This step will use some functions in the key_process class
#################################
'''


Data_Processing = DataProcess() #Call the Data Process class 
#Return the result
Chain_TextIn = [[0 for x in range(64)] for y in range(nBlock)]
Hexa_Return ='' #This is the final encryption text
for k in range (0,nBlock):
    Chain_TextIn[k] = TextIn[k*64:(k+1)*64]
for ii in range (0,nBlock):
    #XOR plain text with the Initialize Vector
    if ii ==0: 
        TextIn1 = np.bitwise_xor(Chain_TextIn[ii],IV)
        ArrayText,EncryptText = Data_Processing.process_text(TextIn1,KeyA)
        Hexa_Return = EncryptText
    else:
        TextIn1 = np.bitwise_xor(Chain_TextIn[ii],ArrayText)
        ArrayText,EncryptText = Data_Processing.process_text(TextIn1,KeyA)
        Hexa_Return = Hexa_Return+EncryptText

print "This is the encrypt text - it is in hexadecimal form \n"
print "                 " + Hexa_Return
print "\n ****************  Finish  ******************************\n"

