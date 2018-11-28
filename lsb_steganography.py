#!/usr/bin/python3

from hashlib import md5
# -*- coding: utf-8 -*-

from _md5 import md5
from base64 import urlsafe_b64encode

from PIL import Image
import random

from cryptography.fernet import Fernet

from custom_exceptions import PasswordError, FileError, DataError

DIST = 8


def normalize_pixel(r, g, b):
    """
    pixel color normalize
    :param r: int
    :param g: int
    :param b: int
    :return: (int, int, int)
    """
    if is_modify_pixel(r, g, b):
        seed = random.randint(1, 3)
        if seed == 1:
            r = _normalize(r)
        if seed == 2:
            g = _normalize(g)
        if seed == 3:
            b = _normalize(b)
    return r, g, b


def modify_pixel(r, g, b):
    """
    pixel color modify
    :param r: int
    :param g: int
    :param b: int
    :return: (int, int, int)
    """
    return map(_modify, [r, g, b])


# Returns the encrypted/decrypted form of string depending upon mode input
def encrypt_decrypt(string, password, mode='enc'):
    _hash = md5(password.encode()).hexdigest()
    cipher_key = urlsafe_b64encode(_hash.encode())
    cipher = Fernet(cipher_key)
    if mode == 'enc':
        return cipher.encrypt(string.encode()).decode()
    else:
        return cipher.decrypt(string.encode()).decode()


def is_modify_pixel(r, g, b):
    """
    :param r: int
    :param g: int
    :param b: int
    :return: bool
    """
    return r % DIST == g % DIST == b % DIST == 1


def _modify(i):
    if i >= 128:
        for x in range(DIST + 1):
            if i % DIST == 1:
                return i
            i -= 1
    else:
        for x in range(DIST + 1):
            if i % DIST == 1:
                return i
            i += 1
    raise ValueError


def _normalize(i):
    if i >= 128:
        i -= 1
    else:
        i += 1
    return i


def normalize(path, output):
    """
    normalize image
    :param path: str
    :param output: str
    """
    img = Image.open(path)
    img = img.convert('RGB')
    size = img.size
    new_img = Image.new('RGB', size)

    for y in range(img.size[1]):
        for x in range(img.size[0]):
            r, g, b = img.getpixel((x, y))
            _r, _g, _b = normalize_pixel(r, g, b)
            new_img.putpixel((x, y), (_r, _g, _b))
    new_img.save(output, "PNG", optimize=True)


def hide_text(path, text, password=None, progressBar=None):
    """
    hide text to image
    :param path: str
    :param text: str
    """
    if password != None:
        text = encrypt_decrypt(text, password, 'enc')  # If password is provided, encrypt the data with given password
    else:
        text = text

    # convert text to hex for write
    write_param = []
    _base = 0
    for _ in str2bin(text):
        write_param.append(int(_, 16) + _base)
        _base += 16

    # hide hex-text to image
    img = Image.open(path)
    if img is None:
        raise FileError("The image file '{}' is inaccessible".format(path))
    height, width = img.size[0], img.size[1]
    counter = 0

    encoding_capacity = height * width * 3
    total_bits = 32 + len(text) * 7
    if total_bits > encoding_capacity:
        raise DataError("The data size is too big to fit in this image!")

    for y in range(width):
        for x in range(height):
            if counter in write_param:
                r, g, b = img.getpixel((x, y))
                r, g, b = modify_pixel(r, g, b)
                img.putpixel((x, y), (r, g, b))
            counter += 1
    # save
    img.save(path, "PNG", optimize=True)


# Returns binary representation of a string
def str2bin(s):
    return ''.join((bin(ord(i))[2:]).zfill(7) for i in s)


# Returns text representation of a binary string
def to_str(s):
    return ''.join(chr(int(s[i:i + 7], 2)) for i in range(len(s))[::7])


def read_text(path, password=None):
    """
    read secret text from image
    :param path: str
    :return: str
    """
    img = Image.open(path)
    if img is None:
        raise FileError("The image file '{}' is inaccessible".format(path))
    counter = 0
    result = []
    height, width = img.size[0], img.size[1]
    for y in range(width):
        for x in range(height):
            r, g, b = img.getpixel((x, y))
            if is_modify_pixel(r, g, b):
                result.append(counter)
            counter += 1
            if counter == 16:
                counter = 0

    if password == None:
        return to_str(''.join([hex(_)[-1:] for _ in result]))
    else:
        try:
            return encrypt_decrypt(to_str(''.join([hex(_)[-1:] for _ in result])), password, 'dec')
        except:
            raise PasswordError("Invalid password!")


class Steganography(object):
    @classmethod
    def encode(cls, input_image_path, output_image_path, encode_text, password):
        """
        hide text to image
        :param input_image_path: str
        :param output_image_path: str
        :param encode_text: str
        """
        normalize(input_image_path, output_image_path)
        hide_text(output_image_path, encode_text, password)
        assert read_text(output_image_path, password) == encode_text, read_text(output_image_path, password)

    @classmethod
    def decode(cls, image_path, password):
        """
        read secret text from image
        :param image_path: str
        :return: str
        """
        return read_text(image_path, password)


if __name__ == "__main__":

    ch = int(input('What do you want to do?\n\n1.Encrypt\n2.Decrypt\n\nInput(1/2): '))
    if ch == 1:
        ip_file = input('\nEnter cover image name(path)(with extension): ')
        text = input('Enter secret data: ')
        pwd = input('Enter password: ')
        op_file = input('Enter output image name(path)(with extension): ')
        try:
            loss = Steganography.encode(ip_file, text, op_file, pwd)
        except FileError as fe:
            print("Error: {}".format(fe))
        except DataError as de:
            print("Error: {}".format(de))
        else:
            print('Encoded Successfully!\nImage Data Loss = {:.5f}%'.format(loss))
    elif ch == 2:
        ip_file = input('Enter image path: ')
        pwd = input('Enter password: ')
        try:
            data = Steganography.decode(ip_file, pwd)
        except FileError as fe:
            print("Error: {}".format(fe))
        except PasswordError as pe:
            print('Error: {}'.format(pe))
        else:
            print('Decrypted data:', data)
    else:
        print('Wrong Choice!')
