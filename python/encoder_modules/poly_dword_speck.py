#!/usr/bin/python

"""
DWORD SPECK 32/64 encoder

SPECK implementation based on https://github.com/bozhu/NSA-ciphers/blob/master/speck.py

Features:
	+ Uses SPECK 32/64 block cipher

Note:
	* Currently we use SPECK 32/64 with a 32-bit key extended to 64-bit key due to register size limitations
	  since we are aiming for evasion of trivial (eg. within order of ~seconds or similar acceptable levels for EBNIDS)
	  cryptanalysis (eg. X-raying, etc.) rather than serious cryptographic strength this is sufficient.

	* We switched encryption and decryption (encoder decrypts plaintext, decoder encrypts ciphertext) since
	  encryption requires only usage of the feistel function (as opposed to inverted feistel function too)
	  for both key expansion and block encryption.

	* SPECK parameters (block- and keysize) can of course be extended to full cryptographic strength if so desired in future releases.

	* Currently we use SPECK in CBC mode which is vulnerable to bitflipping but since an IDS adversary could flip arbitrary bits
	  in the plain/decoder part of our shellcode this is irrelevant.

TODO:
	- Support SPECK 64/64 or full cryptographic strength (SPECK 128/128)
	  eg. have key_reg point to memory blob filled by key_filler
	- Add light polymorphism	
	- Add more decoder stub types	
"""

from basic_xor import basic_xor
from assembler.assembler import assembler
from random import choice
from arch.core import word_keywords, ctr_regs, byte_packs, bit_packs
from utils.rand import rand_bytes
from struct import pack, unpack

class SPECK:
	def __init__(self, master_key=None):
		self.block_size = 32
		self.key_size = 64
		self.__num_rounds = 22
		self.__alpha = 7
		self.__beta = 2
		self.__dim = self.block_size / 2
		self.__mod = 1 << self.__dim
		self.__round_key = []

		if not(master_key == None):
			self.change_key(master_key)

	def __rshift(self, x, i):
		assert i in (self.__alpha, self.__beta)
		return ((x << (self.__dim - i)) % self.__mod) | (x >> i)

	def __lshift(self, x, i):
		assert i in (self.__alpha, self.__beta)
		return ((x << i) % self.__mod) | (x >> (self.__dim - i))

	def __first_feistel(self, x, y):
		return y, (self.__rshift(x, self.__alpha) + y) % self.__mod

	def __second_feistel(self, x, y):
		return y, self.__lshift(x, self.__beta) ^ y

	def change_key(self, master_key):
		assert 0 <= master_key < (1 << self.key_size)
		self.__master_key = master_key
		self.__round_key = [master_key % self.__mod]
		master_key >>= self.__dim
		llist = []
		for i in range(self.key_size / self.__dim - 1):
			llist.append(master_key % self.__mod)
			master_key >>= self.__dim
		for i in range(self.__num_rounds - 1):
			l, r = self.__first_feistel(llist[i], self.__round_key[i])
			r ^= i
			l, r = self.__second_feistel(l, r)
			llist.append(l)
			self.__round_key.append(r)

	def get_key(self):
		return self.__master_key

	def get_keyschedule(self):
		return self.__round_key

	def get_keysize(self):
		return self.key_size

	def __first_feistel(self, x, y):
		return y, (self.__rshift(x, self.__alpha) + y) % self.__mod

	def __second_feistel(self, x, y):
		return y, self.__lshift(x, self.__beta) ^ y

	def __first_feistel_inv(self, x, y):
		return self.__lshift((y - x) % self.__mod, self.__alpha), x

	def __second_feistel_inv(self, x, y):
		return self.__rshift(x ^ y, self.__beta), x

	def decrypt(self, ciphertext):
		assert 0 <= ciphertext < (1 << self.block_size)
		l = ciphertext >> self.__dim
		r = ciphertext % self.__mod
		for i in range(self.__num_rounds - 1, -1, -1):
			l, r = self.__second_feistel_inv(l, r)
			r ^= self.__round_key[i]
			l, r = self.__first_feistel_inv(l, r)
		plaintext = (l << self.__dim) | r
		assert 0 <= plaintext < (1 << self.block_size)
		return plaintext

class poly_dword_speck(basic_xor):
	def __init__(self, plaintext_buf):
		self.decoder_key_offset = -1
		self.block_size = 4
		self.key_size = 4
		self.plaintext_buf = plaintext_buf
		self.encoded_buf = ""
		self.iv = 0x00
		self.block_count = 0
		return

	#
	# Encodes a buffer using SPECK 32/64 in CBC mode.
	# Decryption and encryption are swapped for efficiency reasons
	#
	def encode(self, key, badchars = ""):
		if not((self.block_size in byte_packs)):
			raise Exception("[-]encode_block: Invalid block_size specified")

		if (not(self.key_size in byte_packs)):
			raise Exception("[-]encode_block: Invalid key_size specified")

		# Init SPECK component
		self.speck = SPECK()

		# Repeat or truncate master key depending on limitations
		if((self.speck.get_keysize() / 8) > self.key_size):
			assert((self.speck.get_keysize() / 8) % self.key_size == 0)
			repeat = ((self.speck.get_keysize() / 8) / self.key_size)
			self.speck.change_key(unpack(byte_packs[self.key_size * repeat], key * repeat)[0])			
		elif((self.speck.get_keysize() / 8) < self.key_size):
			assert(self.key_size % (self.speck.get_keysize() / 8) == 0)
			trunc = (self.key_size / (self.speck.get_keysize() / 8))
			self.speck.change_key(unpack(byte_packs[self.key_size / trunc], key[0: (self.speck.get_keysize() / 8)])[0])
		else:
			self.speck.change_key(unpack(byte_packs[self.key_size], key)[0])

		# Padding where necessary
		if(len(self.plaintext_buf) < self.block_size):
			self.plaintext_buf += rand_bytes(self.block_size - len(self.plaintext_buf))
		elif(len(self.plaintext_buf) % self.block_size != 0):
			self.plaintext_buf += rand_bytes(self.block_size - (len(self.plaintext_buf) % self.block_size))

		# Generate IV
		cblock = rand_bytes(self.block_size, badchars)
		self.iv = unpack(byte_packs[self.block_size], cblock)[0]
		self.block_count = 0

		# CBC mode of operation
		for i in xrange(0, len(self.plaintext_buf), self.block_size):
			#plaintext block
			pblock = unpack(byte_packs[self.block_size], self.plaintext_buf[i: i+self.block_size])[0]
			#decrypt
			dblock = self.speck.decrypt(pblock)
			# XOR with previous cblock or IV
			dblock ^= unpack(byte_packs[self.block_size], cblock)[0]
			# new cblock
			cblock = pack(byte_packs[self.block_size], pblock)
			
			# Add to ciphertext buffer
			self.encoded_buf += pack(byte_packs[self.block_size], dblock)

			self.block_count += 1

		return self.encoded_buf

	#
	# SPECK 32/64 decoder stub
	#
	# getpc_reg:	   registry holding PC
	# key_reg:  	   registry holding round key table masking key
	# keyfiller_size:  size of keyfiller stub
	# arch: 		   architecture
	# bits: 		   32 or 64
	#
	def decoder_stub(self, getpc_reg, key_reg, keyfiller_size, arch, bits):

		if(len(self.encoded_buf) < 1):
			raise Exception("[-]decoder_stub: no encoded_buf to work with")

		# registry size
		half_reg_width = bits/2
		reg_size = 2**bits

		# counter register
		ctr_reg = ctr_regs[bits]

		# word keywords
		half_word_keyword = word_keywords[bits/2]
		word_keyword = word_keywords[bits]

		# no conflicts
		if((getpc_reg == ctr_reg) or (key_reg == ctr_reg) or (getpc_reg == key_reg)):
			raise Exception("[-]decoder_stub: specified invalid getpc_reg (%s) or key_reg (%s)", getpc_reg, key_reg)

		# number of blocks
		ctr_sub_val = -(self.block_count)

		# null instruction
		null_ctr_instructions = ['XOR', 'SUB']
		null_ctr_instr = choice(null_ctr_instructions)

		# static for now due to miasm problems
		decoder_len = 128+58

		variables = {'half_reg_width': half_reg_width, 'cbc_iv': self.iv, 'half_word_keyword': half_word_keyword, 'word_keyword': word_keyword, 'decoder_len': decoder_len, 'block_size': self.block_size, 'getpc_reg': getpc_reg, 'key_reg': key_reg, 'ctr_reg': ctr_reg, 'ctr_sub_val': ctr_sub_val, 'null_ctr_instr': null_ctr_instr, 'reg_size': reg_size, 'keyfiller_size': keyfiller_size}

		listing = '''
main:
    SUB    {getpc_reg}, (-(({decoder_len}) + {keyfiller_size}) % {reg_size})
_decoder_begin:
    PUSH   {getpc_reg}

    JMP _start_decoder

    ;
    ; SPECK 32/64 feistel function
    ;
    _speck_feistel_f:
        ; n = 16 => alpha = 7, beta = 2
        ROR AX, 7   ; (L >> alpha)
        ADD AX, BX  ; ((L >> alpha) + R mod word_size)
        XOR AX, DX  ; L' = (((L >> alpha) + R mod word_size) ^ Ki)
        ROL BX, 2   ; (R << beta)
        XOR BX, AX  ; R' = ((R << beta) ^ (((L >> alpha) + R mod word_size) ^ Ki))
        RET

    _start_decoder:

    ; Init master key
    
    ; key_reg low to DI and SI
    MOV EDI, {key_reg}
    MOV SI, DI
    
    ; key_reg high to DX and BX
    ROR {key_reg}, ({half_reg_width}) ; rotate right for higher half
    MOV EDX, {key_reg}    
    MOV BX, DX

    ; Round count
    MOV ECX, 22         ; Round count

    ; Allocate stack space
    SUB ESP, 2*22    ; round key table space
    MOV EAX, ESP

    ; Init round key table
    _schedule_key:

        MOV {half_word_keyword} PTR [EAX+0], DI    ; round_key[0] = K[0]

        ; allocate llist
        SUB ESP, 2*24
        MOV EDI, ESP

        PUSH ECX

        MOV {half_word_keyword} PTR [EDI+0], DX    ; llist[0] = K[1]
        MOV {half_word_keyword} PTR [EDI+2], SI    ; llist[1] = K[2]
        MOV {half_word_keyword} PTR [EDI+4], BX    ; llist[2] = K[3]

        MOV CX, 1

        _expansion_loop:
            PUSH EAX

            MOV EDX, ECX
            DEC DX                      ; DX = i = (CX-1)

            MOV BX, {half_word_keyword} PTR [EAX + EDX*2]  ; BX = round_key[i]
            MOV AX, {half_word_keyword} PTR [EDI + EDX*2]  ; AX = llist[i]

            CALL _speck_feistel_f

            MOV DX, AX                  ; L'

            POP EAX

            MOV {half_word_keyword} PTR [EAX + ECX*2], BX      ; round key
            MOV {half_word_keyword} PTR [EDI + ECX*2 + 4], DX  ; l-list element

            INC ECX
            CMP ECX, {word_keyword} PTR [ESP]
            JNZ _expansion_loop

        POP ECX

        ; clean l-list
        ADD ESP, 2*24

    ; Address of round key table
    MOV EBX, EAX

    ; Plaintext & Ciphertext addresses
    MOV ESI, {word_keyword} PTR [ESP+44] ; saved getpc_reg
    MOV EDI, ESI

    ; IV
    MOV EDX, {cbc_iv}
    
    ; Block count
    {null_ctr_instr} {ctr_reg}, {ctr_reg}
	SUB {ctr_reg}, ({ctr_sub_val} % {reg_size})

    ;-------------------
    ; SPECK 32/64 CBC mode 'decryption'
    ; (swapped encryption and decryption functions for performance reasons)
    ;
    ; ESI = ciphertext address
    ; EDI = plaintext address
    ; EDX = IV
    ; EBX = round key table address
    ; ECX = block count
    ;-------------------

    _block_loop:
        ; load ciphertext block
        LODSD

        ; XOR with IV or previous block
        XOR EAX, EDX

        XCHG EBX, ESI

        ;
        ; SPECK 32/64 block 'decryption'
        ;

            PUSH ECX
            PUSH EBX
            PUSH EDX

            {null_ctr_instr} {ctr_reg}, {ctr_reg}
            _speck_e_loop:
                ; Round key
                MOV DX, {half_word_keyword} PTR [ESI+ECX*2]

                ; BX = R
                MOV BX, AX
                ; swap halves
                ROL EAX, 16
                ; AX = L

                CALL _speck_feistel_f

                ; swap halves
                ROL EAX, 16
                ; BX = R'
                MOV AX, BX

                INC ECX
                CMP ECX, 22
                JNZ _speck_e_loop

            POP EDX
            POP EBX
            POP ECX

        XCHG EBX, ESI

        ; for next block
        MOV EDX, EAX

        ; store plaintext block
        STOSD
    LOOP _block_loop

    ADD ESP, (2*22)
    POP {getpc_reg}
    JMP {getpc_reg}
payload_body:
'''
		asm = assembler(arch, bits)
		stub = asm.assemble(listing.format(**variables))
		return stub