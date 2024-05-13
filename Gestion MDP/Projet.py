from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import os
import hashlib

class PasswordManager:
   def __init__(self, encryption_key):
       self.passwords = {}
       self.encryption_key = encryption_key
       self.passwords_folder = "passwords"

       if not os.path.exists(self.passwords_folder):
           os.makedirs(self.passwords_folder)
       self.load_passwords()

   def add_password(self, website, username, password):
       combined_string = f"{website}_{username}_{password}"
       entry_id = hashlib.sha256(combined_string.encode()).hexdigest()
       for existing_id, data in self.passwords.items():
           if entry_id == existing_id:
               print("Cet identifiant existe déjà.")
               return
       cipher = AES.new(self.encryption_key, AES.MODE_GCM)
       cipher.update(website.encode())
       encrypted_password, tag = cipher.encrypt_and_digest(password.encode())
       self.passwords[entry_id] = {
           'website': website,
           'username': username,
           'password': encrypted_password,
           'tag': tag,
           'nonce': cipher.nonce
       }
       self.save_passwords()
       print(f"Mot de passe pour {website} ajouté avec succès.")

   def save_passwords(self):
       with open(os.path.join(self.passwords_folder, 'passwords.txt'), 'w') as f:
           for entry_id, data in self.passwords.items():
               f.write(f"Entry ID: {entry_id}\n")
               f.write(f"Website: {data['website']}\n")
               f.write(f"Username: {data['username']}\n")
               f.write(f"Encrypted Password: {base64.b64encode(data['password']).decode()}\n")
               f.write(f"Tag: {base64.b64encode(data['tag']).decode()}\n")
               f.write(f"Nonce: {base64.b64encode(data['nonce']).decode()}\n")
               f.write("\n")

   def load_passwords(self):
       passwords_file = os.path.join(self.passwords_folder, 'passwords.txt')
       if os.path.exists(passwords_file):
           with open(passwords_file, 'r') as f:
               lines = f.readlines()
               current_entry = {}
               entry_id = None
               for line in lines:
                   if line.strip() == "":
                       self.passwords[entry_id] = {
                           'website': current_entry['Website'],
                           'username': current_entry['Username'],
                           'password': base64.b64decode(current_entry['Encrypted Password']),
                           'tag': base64.b64decode(current_entry['Tag']),
                           'nonce': base64.b64decode(current_entry['Nonce'])
                       }
                       current_entry = {}
                       entry_id = None
                   else:
                       key, value = line.strip().split(": ")
                       if key == "Entry ID":
                           entry_id = value
                       else:
                           current_entry[key] = value

   def display_credentials(self):
       print("Identifiants enregistrés:")
       for i, (entry_id, data) in enumerate(self.passwords.items(), 1):
           cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=data['nonce'])
           cipher.update(data['website'].encode())
           decrypted_password = cipher.decrypt_and_verify(data['password'], data['tag']).decode()
           print(f"{i}. \nEntry ID: {entry_id}, \nWebsite: {data['website']}, \nUsername: {data['username']}, \nPassword: {decrypted_password}\n")

   def delete_password(self, index):
       if index <= len(self.passwords) and index > 0:
           entry_id_to_delete = list(self.passwords.keys())[index - 1]
           del self.passwords[entry_id_to_delete]
           self.save_passwords()
           print(f"Identifiant pour {entry_id_to_delete} supprimé avec succès.")
       else:
           print("Indice invalide.")

def show_menu():
   print("Menu:")
   print("1. Ajouter un mot de passe")
   print("2. Afficher les identifiants")
   print("3. Supprimer un identifiant")
   print("0. Quitter")

encryption_key = base64.b64decode("NC3Z0+9RxO4D7WSILddxKQ==")
manager = PasswordManager(encryption_key)

while True:
   show_menu()
   choice = input("Entrez votre choix: ")

   if choice == "1":
       website = input("Entrez le nom du site web: ")
       username = input("Entrez votre nom d'utilisateur: ")
       password = input("Entrez votre mot de passe: ")
       manager.add_password(website, username, password)
   elif choice == "2":
       manager.display_credentials()
   elif choice == "3":
       manager.display_credentials()
       index = int(input("Entrez le numéro de l'identifiant à supprimer: "))
       manager.delete_password(index)
   elif choice == "0":
       print("Merci d'avoir utilisé le gestionnaire de mots de passe.")
       break
   else:
       print("Choix invalide. Veuillez entrer un choix valide.")