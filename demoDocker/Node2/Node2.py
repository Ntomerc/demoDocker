# Initial Settings
from openfhe import *
import requests
import tempfile
import os
# import openfhe.PKESchemeFeature as Feature
fun deserialize_decrypt(v1, v2, multiplicative_depth):
    datafolder = 'demoData'
    serType = BINARY # BINARY or JSON
    base_url = 'http://localhost:3000/prova'

    print("This program requres the subdirectory `" + datafolder + "' to exist, otherwise you will get an error writing serializations.")

    # Sample Program: Step 1: Set CryptoContext
    parameters = CCParamsBFVRNS()
    parameters.SetPlaintextModulus(65537)
    parameters.SetMultiplicativeDepth(2)

    cryptoContext = GenCryptoContext(parameters)
    # Enable features that you wish to use
    cryptoContext.Enable(PKESchemeFeature.PKE)
    cryptoContext.Enable(PKESchemeFeature.KEYSWITCH)
    cryptoContext.Enable(PKESchemeFeature.LEVELEDSHE)


    # Sample Program: Step 4: Evaluation

    # OpenFHE maintains an internal map of CryptoContext objects which are
    # indexed by a tag and the tag is applied to both the CryptoContext and some
    # of the keys. When deserializing a context, OpenFHE checks for the tag and
    # if it finds it in the CryptoContext map, it will return the stored version.
    # Hence, we need to clear the context and clear the keys.
    cryptoContext.ClearEvalMultKeys()
    cryptoContext.ClearEvalAutomorphismKeys()
    ReleaseAllContexts()

    # Deserialize the crypto context
    url= base_url+"/cryptocontext"
    response = requests.get(url)

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(response.content)
        temp_file_path = temp_file.name

    # Deserialize the crypto context
    cc, res = DeserializeCryptoContext(temp_file_path, serType)

    # Elimina il file temporaneo dopo averlo usato
    os.unlink(temp_file_path)
    if not res:
    raise Exception("Error reading serialization of the crypto context from cryptocontext.txt")
    print("The cryptocontext has been deserialized.")


    # Deserialize the public key
    url= base_url+"/key-public"
    response = requests.get(url)

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(response.content)
        temp_file_path = temp_file.name

    pk, res = DeserializePublicKey(temp_file_path, serType)

    # Elimina il file temporaneo dopo averlo usato
    os.unlink(temp_file_path)
    if not res:
    raise Exception("Error reading serialization of the public key from key-public.txt")
    print("The public key has been deserialized.")


    url= base_url+"/key-eval-mult"
    response = requests.get(url)

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(response.content)
        temp_file_path = temp_file.name
    if not cc.DeserializeEvalMultKey(temp_file_path,serType):
    raise Exception("Could not deserialize the eval mult key file")
    os.unlink(temp_file_path)
    print("The relinearization key has been deserialized.")

    url= base_url+"/key-eval-rot"
    response = requests.get(url)
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(response.content)
        temp_file_path = temp_file.name
    if not cc.DeserializeEvalAutomorphismKey(temp_file_path,serType):
    raise Exception("Could not deserialize the eval rotation key file")
    os.unlink(temp_file_path)
    print("Deserialized the eval rotation keys.")

    # Deserialize the ciphertexts

    url= base_url+"/ciphertext1"
    response = requests.get(url)
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(response.content)
        temp_file_path = temp_file.name
    ct1, res =  DeserializeCiphertext(temp_file_path, serType)
    os.unlink(temp_file_path)

    if not res:
        raise Exception("Could not read the ciphertext")
    print("The first ciphertext has been deserialized.")



    url= base_url+"/ciphertext2"
    response = requests.get(url)
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(response.content)
        temp_file_path = temp_file.name
    ct2, res =  DeserializeCiphertext(temp_file_path, serType)
    os.unlink(temp_file_path)

    if not res:
        raise Exception("Could not read the ciphertext")
    print("The second ciphertext has been deserialized.")


    # Homomorphic addition

    ciphertextAdd = cc.EvalAdd(ct1, ct2)

    # Homomorphic multiplication
    ciphertextMult = cc.EvalMult(ct1, ct2)

    # Homomorphic rotation
    ciphertextRot1 = cc.EvalRotate(ct1, 1)
    ciphertextRot2 = cc.EvalRotate(ct2, 2)

    # Sample Program: Step 5: Decryption
    url= base_url+"/key-private"
    response = requests.get(url)
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(response.content)
        temp_file_path = temp_file.name
    sk, res =  DeserializePrivateKey(temp_file_path, serType)
    os.unlink(temp_file_path)
    if not res:
        raise Exception("Could not read secret key")
    print("The secret key has been deserialized.")

    # Decrypt the result of additions
    plaintextAddResult = cc.Decrypt(sk, ciphertextAdd)

    # Decrypt the result of multiplications
    plaintextMultResult = cc.Decrypt(sk, ciphertextMult)

    # Decrypt the result of rotations
    plaintextRot1 = cc.Decrypt(sk, ciphertextRot1)
    plaintextRot2 = cc.Decrypt(sk, ciphertextRot2)


    # Shows only the same number of elements as in the original plaintext vector
    # By default it will show all coefficients in the BFV-encoded polynomial
    plaintextRot1.SetLength(len(v1))
    plaintextRot2.SetLength(len(v1))

    # Output results
    print("\nResults of homomorphic computations")
    print("#1 + #2 + #3: " + str(plaintextAddResult))
    print("#1 * #2 * #3: " + str(plaintextMultResult))
    print("Left rotation of #1 by 1: " + str(plaintextRot1))
    print("Left rotation of #1 by 2: " + str(plaintextRot2))


    requests.delete(base_url+"/cryptocontext")
    requests.delete(base_url+"/key-public")
    requests.delete(base_url+"/key-eval-mult")
    requests.delete(base_url+"//key-eval-rot")
    requests.delete(base_url+"/ciphertext1")
    requests.delete(base_url+"/ciphertext2")
    requests.delete(base_url+"/ciphertext3")
    requests.delete(base_url+"/key-private")

