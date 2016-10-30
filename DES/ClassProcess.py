import numpy as np
from bitstring import*
import binascii
class KeyProcess(object):
    """ This class contain all the functions to process the key"""

    def ReadFile(self,filename):
        with open(filename) as file:
            array2d= [[int(value1) for value1 in line.split()]for line in file]

        TablePC =[]
        for row in array2d:
            for item in row:
                TablePC.append(item)
        TablePC = np.array(TablePC) #convert list to array
        # TablePC1 is the table that need for the first permutation: "
        file.close()
        return TablePC


    def convert(self,str, chunk_size):
            for i in xrange(0, len(str), chunk_size):
                yield str[i:i+chunk_size]


    def shift2 (self,C00):
        X = np.zeros([17, 28], np.integer)  # initialize 2D array with value '0'
        #assign the first row by the value of C0/D0
        for i in range(0,28):
            X[0][i] = C00[i]
   
        dx =28
        dy = 16
        row=1
        cols=0
        #Now do the shifting
        while row <= dy:
            while cols < dx-1:
                if row in [1,2,9,16]:
                    tt0= X[row-1][0]
                    while cols <dx-1:                
                        X[row][cols] = X[row-1][cols+1]
                        cols +=1
                    X[row][cols]=tt0
            
                else:
                    tt0= X[row-1][0]
                    tt1 = X[row-1][1]
                    while cols <dx-2: #26                            
                        X[row][cols] = X[row-1][cols+2]
                        cols +=1
                    X[row][cols]= tt0 #26
                    cols +=1
                    X[row][cols]=tt1
                    cols +=1
            cols=0
            row +=1
        return X


    def ShiftDeCrypt (self,C00): #No need to use this
        X = np.zeros([17, 28], np.integer)  # initialize 2D array with value '0'
        #assign the first row by the value of C0/D0
        for i in range(0,28): #i runs from 0 to 27
            X[0][i] = C00[i] 
        X[1] = X[0] #first round no ratation
        #######
        dx =28
        dy = 17 #check zero in case erro
        #Now do the shifting
        for row in range (2,dy):
            for cols in range(0,dx):
                if row in [2,9,16]:
                    if cols >= 1:
                        X[row][cols] = X[row-1][cols-1]
                    else:
                        X[row][cols]= X[row-1][27]
            
                else:
                   if cols ==0:
                       X[row][cols]=  X[row-1][26]
                   elif cols ==1:
                       X[row][cols]=  X[row-1][27]                             
                       
                   else: 
                        X[row][cols] = X[row-1][cols-2]
                                                   
            
        return X



    def shift(self, key, array):  #this way can shift with any value of key
        return array[key%len(array):] + array[:key%len(array)]


    def KeyGenerator(self, TempK1):
        Key_Processing = KeyProcess() #Call the KeyProcess class 

        TablePC1 =Key_Processing.ReadFile('TablePC1.txt')
        TempK1 =np.insert(TempK1,0,1)  #Insert '1' to increase index number since the table PC count from 1, not from 0'

        #Do the permatation 1 according to the table PC1
        #trim off the original key from 64 bits to 56 bits
        Permuation1 =TempK1[np.array(TablePC1)] 

        #Split the key (56bits) into left and right halves, C0 and D0
        C0 = Permuation1[0:28]
        D0 = Permuation1[28:]
        #Call the class KeyProcess to do the shifting in the class file
        C= Key_Processing.shift2(C0)
        #C=> after shifting => get 16 left hafl keys in the array X which return from function shifting
        C= C.tolist() #Convert C from array to list
        #shift2(D0) # call funtction to do the right half D0
        D= Key_Processing.shift2(D0)
        D=D.tolist()

        #Initialize a 2d array to contain the key
        KeyA = np.zeros([16, 48], np.integer)  # initialize 2D array with value '0'
        
        TablePC2 = Key_Processing.ReadFile('TablePC2.txt')
               
        for i in range(1,17):
            #Concatenate left hafl and right hafl
            CD= C[i]+D[i] #this concatenate "+" only work with list, not array
                                #also i starts from 1 to 16, array Lkey and Rkey run from 0 to 16
            CD.insert(0,1)   #Insert '1' to increase index number
            #store the first key to the array
            TempCD = np.array(CD) #convert list to array
            #Do the permatation2  according to the table PC2
            K1 =TempCD[np.array(TablePC2)] 
            KeyA[i-1] = K1

        return KeyA




class DataProcess(object):
    '''
    There are 4 steps in the cipher F function
1. Expand 32 bits (R0) to 48 bit (R0_48bit)
2. XOR 48 bit data (R0_48bit) with the first Key (K1), this is the only time subkeys are used
3. Then take the result of XOR to do the S_Box rotation => get the result = 48bits
4. Then do the permutation to get 32 bits
Ln = R(n-1)
Rn = L(n-1) XOR F[R(n-1), Kn]

    '''
    def process_text(self,PlainText,KeyK):

        Key_Processing = KeyProcess() #Call the KeyProcess class 
          
        #Read the data input (the plain text to encrypt)
        PlainText = np.insert(PlainText,0,1) #Insert '1' to increase index number since the table IP count from 1, not from 0
        #Read the initiate permuation for the data IP
        TableIP =Key_Processing.ReadFile('TableIP.txt')
        #Do the permatation 1 according to the table Initial Permutation IP
        IP_text =PlainText[np.array(TableIP)] #IP_text is the text after IP"

        #Split the IP text (64bits) into left and right halves, L0 and R0
        L0 = IP_text[0:32]
        R0 = IP_text[32:]
                                        
        ArrayRR = np.zeros([17, 32], np.integer) #initialize a 2d array to contain 16 R blocks of 32 bits data
        ArrayLL = np.zeros([17, 32], np.integer) #This array is for the L data
        ArrayLL[0] = L0 #assign the first row for ArrayLL
        ArrayRR[0]= R0 #save R0 in order to switch to L1, now Ln = R(n-1) = ArrayRR[n-1]

#Step 1: Expand 32 bits R0 to 48 bits
        for n in range(1,17): #iteration 16 rounds
            
            ArrayLL[n] = ArrayRR[n-1]
            Rn = np.insert(ArrayRR[n-1],0,1) #to increase index from 0 to 1
                #Read E table to expand 32bits data to 48 bits
            E_table = Key_Processing.ReadFile('TableE.txt')
                #Expand the right R0 data 32bits to 48 bits
            Rn = Rn[np.array(E_table)]
           
#Step 2: XOR with the key
 
            KK1 = np.bitwise_xor(KeyK[n-1],Rn) #KK1 has 48 bits
           
#Step 3: Do the S_box 
            BBK= np.zeros([8, 6], np.integer) #initialize a 2d array to contain 8 blocks of 6 bits data
                #Break the data into 8 blocks of 6 bits
            for i in range (0,8):
                BBK[i] = KK1[i*6:(i+1)*6]
            StoreD =[] #initialize an array to store data bits after the S Box computing
            for i in range (0,8):
                AA = BBK[i]
                row = str(AA[0]) + str(AA[5])
                cols = str(AA[1]) + str(AA[2]) + str(AA[3]) + str(AA[4])
                
                numb_row = BitArray(bin = row).uint
                numb_Cols = BitArray(bin =cols).uint
                S_Box = str('TableS')+str(i+1) +str('.txt')
                with open(S_Box) as file:
                        array2d= [[int(value1) for value1 in line.split()]for line in file]
                file.close()
                newNumb= array2d[numb_row][numb_Cols]
                StoreD.append(newNumb)
                #To this point StoreD is an array with 8 elements (integer, each element is 4 bits long) 
                # => needed to convert to binary to get 32 bits
            BinD=[]
            for number in StoreD:
                BinD.extend('{0:04b}'.format(number))
            B1=[int(ii) for ii in BinD] #convert string array to int array
          
#Step 4: Do the permutation P
            B1 = np.insert(B1,0,1)
            P_table = Key_Processing.ReadFile('TableP.txt')
            B1 = B1[np.array(P_table)]
            #Finished the F function
          
        #Do XOR between the result of F function with L(n-1)
    
            Rn = np.bitwise_xor(ArrayLL[n-1],B1)
    
            ArrayRR[n] = Rn
          
      #Finish S-Box
        
        ###############"
        #Combine Right and Left, remember to switch Left and right of the Encrypt text
        RL16 = [] 
        RL16.extend(ArrayRR[16])
        RL16.extend(ArrayLL[16])
        
        RL16 = np.insert(RL16,0,1)
        TableIP_1 = Key_Processing.ReadFile('TableIP_1.txt')
        RL16 = RL16[np.array(TableIP_1)]
      
        #RL16 is the final array content the encrypt text in binary
        '''
        Go to this website to double check 
        http://www.roubaixinteractive.com/PlayGround/Binary_Conversion/Binary_To_Text.asp
        http://www.binaryhexconverter.com/hex-to-binary-converter
        http://people.eku.edu/styere/Encrypt/JS-DES.html
        '''

        # "Convert binary back to string"

        KK = ''.join(format(x, 'b') for x in RL16)
        nn = int(KK, 2)
        bin_hexa = Key_Processing.convert(KK,8)
       
        Encrypt= ''.join('{:02x}'.format(int(b, 2)) for b in bin_hexa)

        return RL16, Encrypt


    def Decrypt_text(self,En_Text,KeyK):
        Key_Decrypt = KeyProcess() #Call the KeyProcess class


        #Read the initiate permuation for the data IP
        TableIP =Key_Decrypt.ReadFile('TableIP.txt')
        #Read the data input (the plain text to encrypt)
        #En_input is the array of the input encrypted text
        En_Text = np.insert(En_Text,0,1) #Insert '1' to increase index number since the table IP count from 1, not from 0
        #Do the permatation 1 according to the table Initial Permutation IP
        IP1_text = En_Text[np.array(TableIP)] #IP_text is the text after IP"
        
        #Split the IP encrypted text (64bits) into left and right halves, L0 and R0
        R0 = IP1_text[0:32] #Now R0 will take the first hafl left, opposite with the encryption 
        L0 = IP1_text[32:]
                                
        ArrayRR = np.zeros([17, 32], np.integer) #initialize a 2d array to contain 16 R blocks of 32 bits data
        ArrayLL = np.zeros([17, 32], np.integer) #This array is for the L data
        ArrayLL[0] = R0
        ArrayRR[0]= L0 #save R0 in order to switch to L1, now Ln = R(n-1) = ArrayRR[n-1]
        reverse_i =16 #
      
 #Step 1: Expand 32 bits R0 to 48 bits
        for n in range(1,17): #iteration 16 rounds
            
            ArrayLL[n] = ArrayRR[n-1]
            Rn = np.insert(ArrayRR[n-1],0,1) #to increase index from 0 to 1
                #Read E table to expand 32bits data to 48 bits
            E_table = Key_Decrypt.ReadFile('TableE.txt')
                #Expand the right R0 data 32bits to 48 bits
            Rn = Rn[np.array(E_table)]
          
#Step 2: XOR with the key
            
            KK1 = np.bitwise_xor(KeyK[reverse_i-n],Rn) #KK1 has 48 bits

#Step 3: Do the S_box 
            BBK= np.zeros([8, 6], np.integer) #initialize a 2d array to contain 8 blocks of 6 bits data
                #Break the data into 8 blocks of 6 bits
            for i in range (0,8):
                BBK[i] = KK1[i*6:(i+1)*6]
            StoreD =[] #initialize an array to store data bits after the S Box computing
            for i in range (0,8):
                AA = BBK[i]
                row = str(AA[0]) + str(AA[5])
                cols = str(AA[1]) + str(AA[2]) + str(AA[3]) + str(AA[4])
               
                numb_row = BitArray(bin = row).uint
                numb_Cols = BitArray(bin =cols).uint
                S_Box = str('TableS')+str(i+1) +str('.txt')
                with open(S_Box) as file:
                        array2d= [[int(value1) for value1 in line.split()]for line in file]
                file.close()
                newNumb= array2d[numb_row][numb_Cols]
                StoreD.append(newNumb)
                #To this point StoreD is an array with 8 elements (integer, each element is 4 bits long) 
                # => needed to convert to binary to get 32 bits
            BinD=[]
            for number in StoreD:
                BinD.extend('{0:04b}'.format(number))
            B1=[int(ii) for ii in BinD] #convert string array to int array


#Step 4: Do the permutation P
            B1 = np.insert(B1,0,1)
            P_table = Key_Decrypt.ReadFile('TableP.txt')
            B1 = B1[np.array(P_table)]
            #Finished the F function
          
        #Do XOR between the result of F function with L(n-1)
    
            Rn = np.bitwise_xor(ArrayLL[n-1],B1)
    
            ArrayRR[n] = Rn

      #Finish S-Box
        
        ###############"
        #Combine Right and Left, remember to switch Left and right of the Encrypt text
        RL16 = [] 
        RL16.extend(ArrayRR[16])
        RL16.extend(ArrayLL[16])
        
        RL16 = np.insert(RL16,0,1)
        TableIP_1 = Key_Decrypt.ReadFile('TableIP_1.txt')
        RL16 = RL16[np.array(TableIP_1)]
        #RL16 is the final array content the encrypt text in binary
        '''
        Go to this website to double check 
        http://www.roubaixinteractive.com/PlayGround/Binary_Conversion/Binary_To_Text.asp
        http://www.binaryhexconverter.com/hex-to-binary-converter
        http://people.eku.edu/styere/Encrypt/JS-DES.html
        '''
     
        # "Convert binary back to string"
              
        KK = ''.join(format(x, 'b') for x in RL16)

        bin_str = Key_Decrypt.convert(KK,8)
        Decrypt=''.join(chr(int(b, 2)) for b in bin_str)

        return RL16, Decrypt

