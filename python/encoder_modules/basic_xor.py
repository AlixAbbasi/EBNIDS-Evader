#!/usr/bin/python

"""
Basic XOR encoding functionality ported from MSF
Provides no decoder stub functionality (left to child classes)
"""

from os import urandom
from random import choice
from struct import unpack, pack
from arch.core import byte_packs
from utils.rand import rand_bytes

class basic_xor:
	def __init__(self, plaintext_buf, block_size = 4, key_size = 4):
		self.decoder_key_offset = -1
		self.block_size = block_size
		self.key_size = key_size
		self.plaintext_buf = plaintext_buf
		self.encoded_buf = ""
		return

	def get_block_size(self):
		return self.block_size

	def get_key_size(self):
		return self.key_size

	#
	# Encodes a buffer using XOR.
	#
	def encode(self, key, badchars = ""):
		if not(self.block_size in byte_packs):
			raise Exception("[-]encode_block: Invalid block_size specified")

		if (not(self.key_size in byte_packs) or not(len(key) == self.key_size)):
			raise Exception("[-]encode_block: Invalid key_size specified")

		# Padding where necessary
		if(len(self.plaintext_buf) < self.block_size):
			self.plaintext_buf += urandom(self.block_size - len(self.plaintext_buf))
		elif(len(self.plaintext_buf) % self.block_size != 0):
			self.plaintext_buf += urandom(self.block_size - (len(self.plaintext_buf) % self.block_size))

		self.encoded_buf = ""

		for i in xrange(0, len(self.plaintext_buf), self.block_size):
			self.encoded_buf += self.encode_block(key, self.plaintext_buf[i: i+self.block_size], byte_packs[self.block_size], byte_packs[self.key_size])

		return self.encoded_buf

	#
	# Encodes a block using XOR.
	#
	def encode_block(self, key, block, block_pack, key_pack):
		cblock = unpack(block_pack, block)[0]
		cblock ^= unpack(key_pack, key)[0]
		return pack(block_pack, cblock)

	#
	# Taken from MSF
	#
	# This method finds a compatible key for the supplied buffer based also on
	# the supplied bad characters list. This is meant to make encoders more
	# reliable and less prone to bad character failure by doing a fairly
	# complete key search before giving up on an encoder.
	#
	def find_key(self, badchars):
		# If there are no badchars just generate any random key
		if(badchars == ""):
			return rand_bytes(self.key_size, badchars)

		key_bytes = {}
		bad_keys = self.find_bad_keys(badchars)
		allset = [chr(x) for x in range(0, 0x100)]
		found = False

		while not(found):
			for index in xrange(0, self.key_size):
				good_keys = list(set(allset) - set(bad_keys[index].keys()))

				if(len(good_keys) == 0):
					return None

				key_bytes[index] = choice(good_keys)

			found = True

			for i in key_bytes:
				if(key_bytes[i] in badchars):
					return None

		if (len(key_bytes) != self.key_size):
			return None

		key = ""
		for i in key_bytes:
			key += key_bytes[i]

		return key

  	#
  	# Finds keys that are incompatible with the supplied bad character list.
  	#
	def find_bad_keys(self, badchars):
		if(len(badchars) == 0):
			return []

		bad_keys = [{}]*self.key_size
		byte_idx = 0

    	# Scan through all the badchars and build out the bad_keys array
    	# based on the XOR'd combinations that can occur at certain bytes
    	# to produce bad characters
		for byte in self.plaintext_buf:
			for badchar in badchars:
				bad_keys[byte_idx % self.key_size][chr(ord(byte) ^ ord(badchar))] = True

			byte_idx += 1

		for badchar in badchars:
			for i in xrange(0, self.key_size):
				bad_keys[i][badchar] = True

		return bad_keys