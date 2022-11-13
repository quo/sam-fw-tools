#!/usr/bin/python3

import sys

from util import *

def main(fn, patch):
	with open(fn, 'rb') as f:
		# Setup
		_, _, dest, _, newver, a, _, _, _, addr, _, val2e = r(f, 'BBBBIBBBBBBH')
		eq(dest, 0)
		eq(a, 1)
		eq(addr, 0x04, 0x14)
		eq(val2e, 0x2e)
		# Header 1
		h1size, h1type, a, h2pos, fwpos = r(f, '5I')
		eq(h1type, 1)
		eq(h1size, 0x14)
		# Data
		f.seek(0)
		data = f.read()
	data = bytearray(data[:-2]) # discard CRC
	for line in open(patch):
		line = line.strip()
		if not line or line[0] == '#': continue
		offset = 0
		if line.startswith('FW+'):
			offset = 16 + fwpos
			line = line[3:]
		colon = line.index(':')
		arrow = line.index('->')
		addr = int(line[:colon], 0) + offset
		dataorig = parse_hex(line[colon+1:arrow])
		datanew = parse_hex(line[arrow+2:])
		eq(len(dataorig), len(datanew))
		eq(dataorig, data[addr:addr+len(dataorig)])
		data[addr:addr+len(dataorig)] = datanew
	with open(fn+'.patched', 'wb') as f:
		f.write(data)
		f.write(struct.pack('<H', crc16(data[16+fwpos:])))

if __name__ == '__main__':
	_, fn, patch = sys.argv
	main(fn, patch)
