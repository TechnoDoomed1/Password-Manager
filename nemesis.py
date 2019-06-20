# coding=<utf-8>
# This module has a working implementation of the NEMESIS cryptosystem to protect
# my passwords (invented by Eric Santiño Cervera).


class KeyStream:
    """Implementation of a NEMESIS keystream. The cryptosystem uses 2 of those
    to encrypt and decrypt data."""

    def __init__(self, key1, key2):
        """Creates a keystream of random byte values based on the keys supplied,
        stored compactly as a triangular matrix."""
        self.rows = len(key1)//2 + len(key1) % 2
        self.columns = len(key1)
        self.t_matrix = [[] for i in range(self.rows)]

        # Initialize first row.
        self.t_matrix[0] = [ord(key1[j]) for j in range(self.columns)]

        # Populate the rest of the rows.
        for i in range(1, self.rows):
            for j in range(self.columns - i):
                aux = self.t_matrix[i-1][j] * self.t_matrix[i-1][self.columns-i]
                aux += self.t_matrix[i-1][j+1] * self.t_matrix[i-1][j-1 if j > 0 else 0]

                for k in range(len(key2)):
                    tmp = ord(key2[k]) * ord(key2[(k + j) % len(key2)])
                    aux += tmp * ord(key2[(k + aux) % len(key1)])

                self.t_matrix[i].append(aux % 256)

    def getByteNumber(self, n):
        """Generates and returns the requested byte number of the keystream."""
        result = sum(self.t_matrix[i][n % (self.columns - i)] for i in range(self.rows))
        return result % 256


class Piece:
    """Stores the start and end byte positions for encrypting and decrpting an
    array of bytes."""
    def __init__(self, start_pos, end_pos):
        self.start, self.end = start_pos, end_pos

    def getLength(self):
        return self.end - self.start


class Nemesis:
    """Implementation of this new and powerful cryposystem."""
    oddInts = range(1, 256, 2)
    inverse = [1, 171, 205, 183, 57, 163, 197, 239, 241, 27, 61, 167, 41, 19, 53, 223,
               225, 139, 173, 151, 25, 131, 165, 207, 209, 251, 29, 135, 9, 243, 21,
               191, 193, 107, 141, 119, 249, 99, 133, 175, 177, 219, 253, 103, 233,
               211, 245, 159, 161, 75, 109, 87, 217, 67, 101, 143, 145, 187, 221, 71,
               201, 179, 213, 127, 129, 43, 77, 55, 185, 35, 69, 111, 113, 155, 189,
               39, 169, 147, 181, 95, 97, 11, 45, 23, 153, 3, 37, 79, 81, 123, 157, 7,
               137, 115, 149, 63, 65, 235, 13, 247, 121, 227, 5, 47, 49, 91, 125, 231,
               105, 83, 117, 31, 33, 203, 237, 215, 89, 195, 229, 15, 17, 59, 93, 199,
               73, 51, 85, 255]

    def __init__(self, key1, key2):
        """Computes both keystreams from a masterkey for encrypting/decrypting."""
        self.streamA = KeyStream(key1, key2)
        self.streamB = KeyStream(key2, key1)
        self.used_bytes = 0

    def requestNewPiece(self, b_array):
        """Requests a synchronized piece of both streams for a byte array so that
        it may be encrypted/decrypted. These pieces should be unique: never reuse
        the same piece."""
        piece = Piece(self.used_bytes, self.used_bytes + len(b_array))
        self.used_bytes += len(b_array)
        return piece

    def toHexadecimal(self, b_array):
        """Returns the hexadecimal representation of the given array of bytes."""
        return ''.join("%2x" % element for element in b_array)

    def fromHexadecimal(self, hex_str):
        """Returns the array of bytes that constitutes the given hexedecimal string."""
        return bytes(int(hex_str[2*k : 2*(k+1)], base=16) for k in range(len(hex_str)//2))

    def decrypt(self, b_array, index_offset):
        """Uses RK+ decryption on the given array of bytes."""
        result = []

        for index, byte in enumerate(b_array):
            i = index + index_offset

            byte1 = self.streamA.getByteNumber(i)
            byte2 = self.streamB.getByteNumber(i)
            RK = ((byte1 + byte2) % 256) // 2

            tmp = (self.inverse[127 - RK] * byte - byte1 + byte2) * self.inverse[RK]
            result.append(tmp % 256)

        return bytes(result)

    def encrypt(self, b_array, index_offset):
        """Uses RK+ encryption on the given array of bytes."""
        result = []

        for index, byte in enumerate(b_array):
            i = index + index_offset

            byte1 = self.streamA.getByteNumber(i)
            byte2 = self.streamB.getByteNumber(i)
            RK = ((byte1 + byte2) % 256) // 2

            tmp = (self.oddInts[RK] * byte + byte1 - byte2) * self.oddInts[127 - RK]
            result.append(tmp % 256)

        return bytes(result)
