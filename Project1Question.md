# Projet filecrypt
by Yanis MEZIANE and Thomas ARTRU
##1
Nous avons choisi d'implémenter  un chiffrement AES avec un mode CBC refait par nos soins.
De plus nous avons implémenter le mode CTS pour répondre a la contrainte de garder la même longeur de fichier entre le chiffré et le clair.
## 2
Pour dériver la clé à partir du mot de passe nous avons utilisé
PBKDF2WithHmacSHA256, présent par défaut. Cette algorithme satisfait les standards PKCS11
## 3
La longeur du mode de passe doit faire :
62^x = 2^128 => x = 21,4 soit 22 caractere pour assurer une sécurité de 128 bits
## 4
Nous utilisons le meme algo de dérivation que pour la question 2 sauf que nous ajoutons en plus le nom du fichier au mot de passe
## 5
La taille de l'archive et la meme que la taille de la somme des fichiers. Ce resultat est logique car une fois chiffré il n'y doit y avoir aucun patern qui se répète le fichier est donc incomprésible.
## 6
Si on modifie un ficgier chiffré on observe une répercusion sur les blocs suivants. Ce qui est logique en considérant le mode utilisé.
## 7
Le hmac étant unique pour un fichier en entré cela permet de vérifier l'authenticité des fichiers chiffrés.
