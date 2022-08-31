def encryptSubstitutionCipher(plaintext, key):
    ciphertext = ""
    for c in plaintext:
        if c.isalpha():
            if c.isupper():
                ciphertext += chr((ord(c) - ord('A') + key) % 26 + ord('A'))
            else:
                ciphertext += chr((ord(c) - ord('a') + key) % 26 + ord('a'))
        else:
            ciphertext += c
    return ciphertext

def decryptSubstitutionCipher(ciphertext, key):
    plaintext = ""
    for c in ciphertext:
        if c.isalpha():
            if c.isupper():
                plaintext += chr((ord(c) - ord('A') - key) % 26 + ord('A'))
            else:
                plaintext += chr((ord(c) - ord('a') - key) % 26 + ord('a'))
        else:
            plaintext += c
    return plaintext



def main():
    plaintext = input("Enter plaintext: ")
    key = int(input("Enter key: "))
    # print("Plain text is: ", plaintext)
    # print("Key is: ", key)
    ciphertext = encryptSubstitutionCipher(plaintext, key)
    print("Ciphertext: " + ciphertext)
    decryptedtext = decryptSubstitutionCipher(ciphertext, key)
    if plaintext != decryptedtext:
        print("Decryption failed")
        print("Decrypted text: " + decryptedtext)
    else:
        print("Decrypted text: " + decryptedtext)

if __name__ == "__main__":
    main()