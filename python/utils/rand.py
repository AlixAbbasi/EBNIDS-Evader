#!/usr/bin/python

"""
Basic random bytes utils
"""

from struct import pack, unpack
from random import choice
from os import urandom
from string import ascii_letters, ascii_lowercase, ascii_uppercase, digits, hexdigits, letters, lowercase, uppercase, printable, whitespace
from arch.core import bit_packs

def contains_badchars(buf, badchars):
	return list(set(buf).intersection(badchars))

def rand_bytes(count, badchars = ""):
	buf = urandom(count)
	while(contains_badchars(buf, badchars)):
		buf = urandom(count)
	return buf

def rand_word_key_pair(size, badchars):
	packer = bit_packs[size*8]

	word = rand_bytes(size, badchars)
	key = rand_bytes(size, badchars)
	res_val = pack(packer, (unpack(packer, word)[0] ^ unpack(packer, key)[0])) # TODO: make sure res_val doesn't contain badchars either
	return word, key, res_val