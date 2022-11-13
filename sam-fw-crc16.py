#!/usr/bin/python3

import sys

from util import *

def main(fn):
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
		f.seek(16 + fwpos)
		data = f.read()
	crc, = struct.unpack('<H', data[-2:])
	crccalc = crc16(data[:-2])
	print('File CRC: 0x%04x' % crc)
	print('Calculated CRC: 0x%04x' % crccalc)
	if crc != crccalc:
		with open(fn, 'r+b') as f:
			f.seek(-2, 2)
			f.write(struct.pack('<H', crccalc))
		print('Updated CRC!')

if __name__ == '__main__':
	_, fn = sys.argv
	main(fn)
