# Initial Settings
from openfhe import *
import requests
import os
# import openfhe.PKESchemeFeature as Feature

datafolder = 'demoData'
base_url = 'http://localhost:3000/prova'

def encrypt_serialize(vectorOfInts1, vectorOfInts2, mult_depth, scale_mod_size, batch_size)
   serType = BINARY # BINARY or JSON
   print("This program requres the subdirectory `" + datafolder + "' to exist, otherwise you will get an error writing serializations.")

   # Sample Program: Step 1: Set CryptoContext
   parameters = CCParamsBFVRNS()
   parameters.SetPlaintextModulus(65537)
   parameters.SetMultiplicativeDepth(mult_depth)

   cryptoContext = GenCryptoContext(parameters)
   # Enable features that you wish to use
   cryptoContext.Enable(PKESchemeFeature.PKE)
   cryptoContext.Enable(PKESchemeFeature.KEYSWITCH)
   cryptoContext.Enable(PKESchemeFeature.LEVELEDSHE)

   # Serialize cryptocontext
   if not SerializeToFile(datafolder + "/cryptocontext.txt", cryptoContext, serType):
      raise Exception("Error writing serialization of the crypto context to cryptocontext.txt")
   else:
      file_path = 'demoData/cryptocontext.txt'

   # Aprire il file in modalità di lettura
      with open(file_path, 'rb') as file:
      # Leggere il contenuto del file
         file_content = file.read()

      # Impostare le intestazioni (headers), se necessario
         headers = {
            'Content-Type': 'text/plain',  # Specificare il tipo di contenuto
            # Aggiungi altre intestazioni se necessario, ad esempio:
            # 'Authorization': 'Bearer <tuo_token>'
         }
         url=base_url+"/cryptocontext"
         # Effettuare la richiesta PUT
         response = requests.put(url, headers=headers, data=file_content)
         print (response)
         print("The cryptocontext has been serialized.")
   # Sample Program: Step 2: Key Generation

   # Generate a public/private key pair
   keypair = cryptoContext.KeyGen()
   print("The keypair has been generated.")

   # Serialize the public key
   if not SerializeToFile(datafolder + "/key-public.txt", keypair.publicKey, serType):
      raise Exception("Error writing serialization of the public key to key-public.txt")
   else:
      file_path = 'demoData/key-public.txt'

   # Aprire il file in modalità di lettura
      with open(file_path, 'rb') as file:
      # Leggere il contenuto del file
         file_content = file.read()

      # Impostare le intestazioni (headers), se necessario
         headers = {
            'Content-Type': 'text/plain',  # Specificare il tipo di contenuto
            # Aggiungi altre intestazioni se necessario, ad esempio:
            # 'Authorization': 'Bearer <tuo_token>'
         }
         url=base_url+"/key-public"
         # Effettuare la richiesta PUT
         response = requests.put(url, headers=headers, data=file_content)
         print (response)
         print("The public key has been serialized.")

   # Serialize the secret key
   if not SerializeToFile(datafolder + "/key-private.txt", keypair.secretKey, serType):
      raise Exception("Error writing serialization of the secret key to key-private.txt")
   else:
      file_path = 'demoData/key-private.txt'

   # Aprire il file in modalità di lettura
      with open(file_path, 'rb') as file:
      # Leggere il contenuto del file
         file_content = file.read()

      # Impostare le intestazioni (headers), se necessario
         headers = {
            'Content-Type': 'text/plain',  # Specificare il tipo di contenuto
            # Aggiungi altre intestazioni se necessario, ad esempio:
            # 'Authorization': 'Bearer <tuo_token>'
         }
         url=base_url+"/key-private"
         # Effettuare la richiesta PUT
         response = requests.put(url, headers=headers, data=file_content)
         print (response)
         print("The secret key has been serialized.")

   # Generate the relinearization key
   cryptoContext.EvalMultKeyGen(keypair.secretKey)
   print("The relinearization key has been generated.")

   # Serialize the relinearization key
   if not cryptoContext.SerializeEvalMultKey(datafolder + "/key-eval-mult.txt",serType):
      raise Exception("Error writing serialization of the eval mult keys to \"key-eval-mult.txt\"")
   else:
      file_path = 'demoData/key-eval-mult.txt'

   # Aprire il file in modalità di lettura
      with open(file_path, 'rb') as file:
      # Leggere il contenuto del file
         file_content = file.read()

      # Impostare le intestazioni (headers), se necessario
         headers = {
            'Content-Type': 'text/plain',  # Specificare il tipo di contenuto
            # Aggiungi altre intestazioni se necessario, ad esempio:
            # 'Authorization': 'Bearer <tuo_token>'
         }
         url=base_url+"/key-eval-mult"
         # Effettuare la richiesta PUT
         response = requests.put(url, headers=headers, data=file_content)
         print (response)
         print("The relinearization key has been serialized.")


   # Generate the rotation evaluation keys
   cryptoContext.EvalRotateKeyGen(keypair.secretKey, [1, 2, -1, -2])
   print("The rotation evaluation keys have been generated.")

   # Serialize the rotation evaluation keys
   if not cryptoContext.SerializeEvalAutomorphismKey(datafolder + "/key-eval-rot.txt",serType):
      raise Exception("Error writing serialization of the eval rotate keys to \"key-eval-rot.txt\"")
   else:
      file_path = 'demoData/key-eval-rot.txt'

   # Aprire il file in modalità di lettura
      with open(file_path, 'rb') as file:
      # Leggere il contenuto del file
         file_content = file.read()

      # Impostare le intestazioni (headers), se necessario
         headers = {
            'Content-Type': 'text/plain',  # Specificare il tipo di contenuto
            # Aggiungi altre intestazioni se necessario, ad esempio:
            # 'Authorization': 'Bearer <tuo_token>'
         }
         url=base_url+"/key-eval-rot"
         # Effettuare la richiesta PUT
         response = requests.put(url, headers=headers, data=file_content)
         print (response)
         print("The rotation evaluation key has been serialized.")


   # Sample Program: Step 3: Encryption

   # First plaintext vector is encoded
   plaintext1 = cryptoContext.MakePackedPlaintext(vectorOfInts1)

   # Second plaintext vector is encoded

   plaintext2 = cryptoContext.MakePackedPlaintext(vectorOfInts2)




   # The encoded vectors are encrypted
   ciphertext1 = cryptoContext.Encrypt(keypair.publicKey, plaintext1)
   ciphertext2 = cryptoContext.Encrypt(keypair.publicKey, plaintext2)
   print("The plaintexts have been encrypted.")

   if not SerializeToFile(datafolder + "/ciphertext1.txt", ciphertext1, serType):
      raise Exception("Error writing serialization of ciphertext 1 to ciphertext1.txt")
   else:
      file_path = 'demoData/ciphertext1.txt'

   # Aprire il file in modalità di lettura
      with open(file_path, 'rb') as file:
      # Leggere il contenuto del file
         file_content = file.read()

      # Impostare le intestazioni (headers), se necessario
         headers = {
            'Content-Type': 'text/plain',  # Specificare il tipo di contenuto
            # Aggiungi altre intestazioni se necessario, ad esempio:
            # 'Authorization': 'Bearer <tuo_token>'
         }
         url=base_url+"/ciphertext1"
         # Effettuare la richiesta PUT
         response = requests.put(url, headers=headers, data=file_content)
         print (response)
         print("The first ciphertext has been serialized.")


   if not SerializeToFile(datafolder + "/ciphertext2.txt", ciphertext2, serType):
      raise Exception("Error writing serialization of ciphertext2 to ciphertext2.txt")
   else:
      file_path = 'demoData/ciphertext2.txt'

   # Aprire il file in modalità di lettura
      with open(file_path, 'rb') as file:
      # Leggere il contenuto del file
         file_content = file.read()

      # Impostare le intestazioni (headers), se necessario
         headers = {
            'Content-Type': 'text/plain',  # Specificare il tipo di contenuto
            # Aggiungi altre intestazioni se necessario, ad esempio:
            # 'Authorization': 'Bearer <tuo_token>'
         }
         url=base_url+"/ciphertext2"
         # Effettuare la richiesta PUT
         response = requests.put(url, headers=headers, data=file_content)
         print (response)
         print("The second ciphertext has been serialized.")

   return (cryptoContext, keypair)

