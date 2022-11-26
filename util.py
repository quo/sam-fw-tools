import struct

def r(f, fmt):
	s = struct.Struct('<'+fmt)
	return s.unpack(f.read(s.size))

def eq(a, *b):
	if a not in b: raise Exception('%r not in %r' % (a,b))

def hexdump(x):
	return ' '.join('%02x' % b for b in x)

def parse_hex(s):
	return bytes(int(x,16) for x in s.split())

def gen_crc16_table():
	for i in range(256):
		crc = i << 8
		for bit in range(8):
			crc = crc << 1
			if crc & 0x10000: crc ^= 0x1021
		yield crc & 0xffff
CRC16_TABLE = list(gen_crc16_table())
def crc16(data):
	crc = 0xffff
	for b in data:
		crc = CRC16_TABLE[((crc >> 8) ^ b) & 0xff] ^ (crc << 8 & 0xffff)
	return crc

def gen_crc32_table():
	for i in range(256):
		crc = i
		for bit in range(8):
			if crc & 1: crc = (crc >> 1) ^ 0xedb88320
			else: crc = crc >> 1
		yield crc & 0xffffffff
CRC32_TABLE = list(gen_crc32_table())
def crc32(data):
	crc = 0xffffffff
	for b in data:
		crc = CRC32_TABLE[(crc ^ b) & 0xff] ^ (crc >> 8)
	return crc ^ 0xffffffff

def fw_version_str(v):
	return '%i.%i.%i' % (v >> 24, v >> 8 & 0xffff, v & 0xff)

