# coding=<utf-8>
# This module has an implementation of a custom password manager, using a dual file
# approach and the use of a new encryption standard.

from hashlib import sha3_256
from nemesis import Nemesis, Piece
from random import sample
from string import ascii_lowercase as lower, ascii_uppercase as upper, digits
import os, pyperclip

var_datafile = ""


class Account:
    """Implements the information of an account as stored in the log file:
    <account_name> <password> <piece>"""

    def __init__(self, string):
        name, password, piece_info = string.split('\t')
        self.name = name
        self.password = password
        self.piece = Piece(*map(int, piece_info.split(':')))

    def __str__(self):
        return "%s\t%s\t%i:%i\n" % (self.name, self.password, self.piece.start, self.piece.end)

    def getPieceStart(self):
        return self.piece.start

    def getPieceLength(self):
        return self.piece.getLength()


class PasswordManager:
    """Implements a password manager that shows all stored accounts that have an
    stored password, and allows to retrieve said password. Also, it allows to
    change existing passwords and add new ones."""

    __masterkey_hash = None

    __options = ("1) Mostrar una contraseña", "2) Cambiar una contraseña",
                 "3) Añadir una nueva contraseña", "4) Salir")

    def __init__(self):
        """Opens the password manager with the specified masterkey. If that key
        doesn't have the correct hash value, ask again."""

        # Necesitamos que el usuario sepa e introduzca una de las 2 contraseñas maestras.
        # Hay una para ordenador, y una para móvil. Luego, entramos en el menú principal.
        print("*" * 90)
        print("¡Bienvenido al Administrador de Contraseñas!\n")

        global var_datafile

        # Si aún no tenemos una contraseña maestra asignada, pedimos al usuario que introduzca una.
        if "hash.dat" not in os.listdir('.'):
            with open("hash.dat", 'wb') as datafile:
                print("Parece que es la primera vez que ejecutas este programa. Por favor, introduce una contraseña maestra.")
                print("Es necesario que tenga un mínimo de 20 carácteres.\n")

                masterkey = ''
                while len(masterkey) < 20:
                    masterkey = input('CONTRASEÑA MAESTRA: ')

                if len(masterkey) % 2 != 0:
                    masterkey = masterkey + '$'

                # El hash de 256 bits de la contraseña en la función SHA3 es guardado, encriptado a su vez mediante la propia
                # contraseña para evitar ataques de colisión contra hashes específicos.
                self.cryptosystem = Nemesis(masterkey[ : len(masterkey)//2], masterkey[len(masterkey)//2 : ])
                hash_value = sha3_256(masterkey.encode('utf-8')).hexdigest().encode('utf-8')
                hash_value = self.cryptosystem.encrypt(hash_value, 0)
                hash_value = self.cryptosystem.toHexadecimal(hash_value)
                datafile.write(hash_value.encode('utf-8'))

                print("¡No olvides tu contraseña maestra! Si la olvidas, no podrás volver a gestionar tus contraseñas.")
                var_datafile = "./datafile.tsv"

        # Si ya había una contraseña maestra asignada, pedimos que la introduzcan, y comparamos su hash con el guardado.
        #
        # NOTA: Aún y si por algún casual hubiera una colisión que permitiera el acceso al Administrador de Contraseñas usando
        # una contraseña maestra errónea, las contraseñas individuales seguirían siendo seguras ya que no se desencriptarían
        # de manera adecuada.
        else:
            with open("hash.dat", 'rb') as datafile:
                self.__masterkey_hash = datafile.read().decode('utf-8')

            while True:
                masterkey = input("Introduce tu contraseña maestra: ")

                if len(masterkey) % 2 != 0:
                    masterkey = masterkey + '$'

                try:
                    hash_value = sha3_256(masterkey.encode('utf-8')).hexdigest()
                    self.cryptosystem = Nemesis(masterkey[ : len(masterkey)//2], masterkey[len(masterkey)//2 : ])
                    masterkey_hash = self.cryptosystem.fromHexadecimal(self.__masterkey_hash)
                    masterkey_hash = self.cryptosystem.decrypt(masterkey_hash, 0).decode('utf-8')
                except BaseException:
                    pass

                if hash_value == masterkey_hash:
                    var_datafile = "./datafile.tsv"
                    self.discardUsedBytes()
                    break
                else:
                    print("ERROR - Contraseña incorrecta.")

        # Finalmente, abrimos el fichero que guarda las contraseñas individuales (si no existe, lo creamos) y entramos al
        # menú del Administrador de Contraseñas.
        if var_datafile not in os.listdir('.'):
            with open(var_datafile, 'w') as datafile:
                pass

        self.getMenuOption()

    def getMenuOption(self):
        """Shows the main menu and allows the user the select one of the options."""

        while True:
            # Show all options in the menu.
            print("=" * 90)
            for option in self.__options:
                print(option)

            # Let the user select option, and execute the corresponding code.
            try:
                option = int(input("Introduce una opción: "))

                if option == 1:
                    self.showPassword()
                elif option == 2:
                    self.changePassword()
                elif option == 3:
                    self.addPassword()
                elif option == 4:
                    break
                else:
                    raise ValueError

            except ValueError:
                print("ERROR - No se ha podido proceder.")

    def selectAccount(self, accounts):
        """Prints on-screen all the different accounts that are stored in the data file,
        and prompts the user to select one. The list is sorted alphabetically, although
        that may not be the case for the log file."""

        # Show all accounts alphabetically.
        accounts.sort(key = lambda x: x.name.lower())

        for selection_index, account in enumerate(accounts):
            print("%2i) %s" % (selection_index + 1, account.name))

        # Return the chosen account.
        while True:
            option = input("De qué cuenta? ")

            try:
                option = int(option)

                if 1 <= option <= len(accounts):
                    return accounts[option - 1]
                else:
                    raise ValueError

            except ValueError:
                print("ERROR - Opción incorrecta.")

    def showPassword(self):
        """Shows the password for a given account. This method is called if the
        user selects the corresponding option in the main menu."""

        # Read the data file and make the user choose the proper account.
        with open(var_datafile, 'r') as data:
            accounts = [Account(line) for line in data.readlines()]
            if not accounts:
                print("No hay cuentas aún guardadas.")
                return
            else:
                chosen_account = self.selectAccount(accounts)

        # Show on-screen the password that is associated to it.
        password = self.cryptosystem.fromHexadecimal(chosen_account.password)
        password = self.cryptosystem.decrypt(password, chosen_account.getPieceStart())
        print('\n' + password.decode('utf-8') + '\n')

        # If possible, try to copy the password to the clipboard.
        try:
            pyperclip.copy(password.decode('utf-8'))
        except:
            pass

    def changePassword(self):
        """Changes the password for a given account. This method is called if the
        user selects the corresponding option in the main menu."""

        # Read the log file and make the user choose the proper account.
        with open(var_datafile, 'r') as data:
            accounts = [Account(line) for line in data.readlines()]
            if not accounts:
                print("No hay cuentas aún guardadas.")
                return
            else:
                chosen_account = self.selectAccount(accounts)

        # Ask the user to introduce the new password.
        new_password = input("Introduce la nueva contraseña: ").encode('utf-8')

        # Request a new piece for the password, and change both the stored
        # password hexadecimal string and piece information.
        chosen_account.piece = self.cryptosystem.requestNewPiece(new_password)
        new_password = self.cryptosystem.encrypt(new_password, chosen_account.getPieceStart())
        chosen_account.password = self.cryptosystem.toHexadecimal(new_password)

        # Commit the changes to the data file.
        with open(var_datafile, 'w') as data:
            data.writelines(str(account) for account in accounts)

    def addPassword(self):
        """Adds a new password for an account that isn't stored as of yet. This
        method is called if the user selects the corresponding option in the
        main menu."""

        # Ask the user to introduce account name, then have the user say if it's 
        # a basic account. Non-basic accounts have a password automatically generated.
        new_name = input("Nombre de la nueva cuenta: ")
        
        if input("Es una cuenta basica (s/n)? ").lower() != 's':
            length = int(input("Longitud de la contraseña final: "))
            new_password = ''.join(sample(lower + upper + digits, length)).encode('utf-8')
        else:
            new_password = input("Introduce la contraseña: ").encode('utf-8')

        # Request a new piece for the password, and process it.
        new_piece = self.cryptosystem.requestNewPiece(new_password)
        new_password = self.cryptosystem.encrypt(new_password, new_piece.start)
        new_password = self.cryptosystem.toHexadecimal(new_password)

        # Add the information to the data file.
        with open(var_datafile, 'a') as data:
            data.write("%s\t%s\t%i:%i\n" % (new_name, new_password,
                                            new_piece.start, new_piece.end))

    def discardUsedBytes(self):
        """Advances the count of already used bytes from the Nemesis cryptosystem
        so that pieces of data already used aren't re-used again, as that would
        be unsafe."""

        with open(var_datafile, 'r') as data:
            try:
                last_byte_used = int(data.readlines()[-1].split(':')[-1])
                self.cryptosystem.used_bytes += last_byte_used
            except IndexError:
                pass


# Run this when the file is run from the terminal.
if __name__ == "__main__":
    PasswordManager()
