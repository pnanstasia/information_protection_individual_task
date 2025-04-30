'module for cryptography task'
import os
import struct
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from PIL import Image
import numpy as np

class ImageSigner:
    """class for signer"""
    def __init__(self, private_key_path=None, public_key_path=None):
        """initialization"""
        self.private_key = None
        self.public_key = None

        if private_key_path:
            self.load_private_key(private_key_path)
        if public_key_path:
            self.load_public_key(public_key_path)

    def generate_keys(self, private_key_path='private_key.pem', public_key_path='public_key.pem'):
        """function to generate both private and public keys"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )

        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        public_key = private_key.public_key()
        with open(public_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        self.private_key = private_key
        self.public_key = public_key

        return private_key, public_key

    def load_private_key(self, private_key_path):
        """loading of the private key"""
        with open(private_key_path, 'rb') as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

    def load_public_key(self, public_key_path):
        """loading of the public key"""
        with open(public_key_path, 'rb') as key_file:
            self.public_key = serialization.load_pem_public_key(
                key_file.read()
            )

    def hash_image(self, image_path):
        """calculate a hash for the image, ignoring the least significant bit of each pixel"""
        image = Image.open(image_path)
        img_array = np.array(image)

        cleaned_array = img_array & 0xFE

        hasher = hashlib.sha256()
        hasher.update(cleaned_array.tobytes())
        return hasher.digest()

    def sign_image(self, image_path, output_path=None):
        """signature of the image and hide it in the LSB"""
        if not self.private_key:
            raise ValueError("Private key wasn't found")

        if output_path is None:
            filename, ext = os.path.splitext(image_path)
            output_path = f"{filename}_signed{ext}"

        image_hash = self.hash_image(image_path)

        signature = self.private_key.sign(
            image_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        image = Image.open(image_path)
        img_array = np.array(image)
        total_pixels = img_array.size
        sig_bits_needed = len(signature) * 8 + 32

        if sig_bits_needed > total_pixels:
            print(f"Image is too small - has {total_pixels} pixels, but required {sig_bits_needed}")

        self._embed_signature(image_path, signature, output_path)

        print(f"Image was signed and saved to the file - {output_path}")
        return signature

    def _embed_signature(self, image_path, signature, output_path):
        """hiding the signature using marker and image format"""
        image = Image.open(image_path)
        img_array = np.array(image).copy()
        if len(img_array.shape) == 2:
            image = image.convert('RGB')
            img_array = np.array(image).copy()

        original_shape = img_array.shape
        flat_array = img_array.flatten()

        marker = "RSSIG"
        marker_bits = np.unpackbits(np.frombuffer(marker.encode('ascii'), dtype=np.uint8))

        sig_len_bytes = struct.pack("<I", len(signature))
        sig_len_bits = np.unpackbits(np.frombuffer(sig_len_bytes, dtype=np.uint8))

        signature_bits = np.unpackbits(np.frombuffer(signature, dtype=np.uint8))

        total_bits = len(marker_bits) + len(sig_len_bits) + len(signature_bits)
        if total_bits > flat_array.size:
            raise ValueError("Image is too small")

        embedding_area = flat_array[:total_bits]
        embedding_area &= 0xFE

        flat_array[:len(marker_bits)] |= marker_bits

        start_idx = len(marker_bits)
        end_idx = start_idx + len(sig_len_bits)
        flat_array[start_idx:end_idx] |= sig_len_bits

        start_idx = end_idx
        end_idx = start_idx + len(signature_bits)
        flat_array[start_idx:end_idx] |= signature_bits

        modified_img_array = flat_array.reshape(original_shape)

        modified_image = Image.fromarray(modified_img_array)
        modified_image.save(output_path)

    def verify_signature(self, image_path):
        """verification of the signature"""
        if not self.public_key:
            raise ValueError("Public key isn't defined")

        image = Image.open(image_path)
        img_array = np.array(image)

        if len(img_array.shape) < 3 and len(img_array.shape) > 0:
            print("Warning, image has 1 channel")

        flat_array = img_array.flatten()
        marker_bits = flat_array[:40] & 0x01
        marker_bytes = np.packbits(marker_bits)
        try:
            marker = marker_bytes.tobytes().decode('ascii')
            if marker != "RSSIG":
                return False
            start_idx = 40
            end_idx = start_idx + 32
            len_bits = flat_array[start_idx:end_idx] & 0x01
            len_bytes = np.packbits(len_bits).tobytes()

            signature_len = struct.unpack("<I", len_bytes)[0]
            if signature_len <= 0 or signature_len > 1024:
                return False

            start_idx = end_idx
            end_idx = start_idx + (signature_len * 8)
            if end_idx > flat_array.size:
                return False
            signature_bits = flat_array[start_idx:end_idx] & 0x01
            signature = np.packbits(signature_bits).tobytes()

            if len(signature) != signature_len:
                return False
            temp_array = img_array.copy()
            temp_array = temp_array & 0xFE

            hasher = hashlib.sha256()
            hasher.update(temp_array.tobytes())
            image_hash = hasher.digest()

            self.public_key.verify(
                signature,
                image_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True

        except UnicodeDecodeError:
            return False, "Marker isn't deco"
        except struct.error:
            return False, "Invalid len of sign"
        except InvalidSignature:
            return False, "Invalid sign"
        except Exception as e:
            return False, f"Error occured - {str(e)}"

def main():
    "main function to run the program"
    private_key_path = 'private_key.pem'
    public_key_path = 'public_key.pem'
    original_image_path = 'image.png'
    signed_image_path = 'signed_image.png'

    signer = ImageSigner()
    signer.generate_keys(private_key_path, public_key_path)

    signer = ImageSigner(private_key_path=private_key_path)
    signer.sign_image(original_image_path, signed_image_path)

    signer = ImageSigner(public_key_path=public_key_path)
    result = signer.verify_signature(signed_image_path)

    if result:
        print("Image was verified, sign is correct")
    else:
        print("Image is fake")

if __name__ == "__main__":
    main()
