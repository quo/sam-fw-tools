#!/usr/bin/python3

import sys, struct

from util import *

def main():
	_, fw0, fw1, elf, newver = sys.argv
	newver = struct.pack('<I', int(newver, 0))

	fns = []

	with open(elf, 'rb') as f:
		eq(f.read(0x1c), b'\x7fELF\1\1\1\0\0\0\0\0\0\0\0\0\2\0\x28\0\1\0\0\0\0\0\0\0')
		phoff, shoff, _, ehsize, phentsize, phnum, shentsize, shnum, stridx = r(f, '3I6H')

		f.seek(shoff + stridx * shentsize)
		sname, stp, sflags, saddr, soffset, ssize = r(f, '6I')

		for i in range(shnum):
			f.seek(shoff + i * shentsize)
			name, tp, flags, addr, offset, size = r(f, '6I')
			if tp == 1 and flags & 4:
				f.seek(soffset + name)
				name = f.read(256)
				name = name[:name.index(0)].decode('ascii').lstrip('.')
				f.seek(offset)
				fns.append((name, addr, f.read(size)))

	with open(fw0, 'rb') as f0:
		with open(fw1, 'rb') as f1:
			f0.seek(0x20)
			fwpos, = r(f0, 'I')
			fwpos += 0x10

			f0.seek(0)
			img = f0.read()
			oldver = img[4:8]
			verpos = -1
			print('# FW version')
			while True:
				verpos = img.find(oldver, verpos+1)
				if verpos < 0: break
				print('0x%08x:' % verpos if verpos < fwpos else 'FW+0x%05x:' % (verpos-fwpos), hexdump(oldver), '->', hexdump(newver))
			print()


			for name, addr, data in fns:
				f0.seek(fwpos + addr)
				f1.seek(fwpos + addr)
				f0old = f0.read(len(data))
				f1old = f1.read(len(data))
				# function must start with push
				eq(f0old[:2], b'\x2d\xe9')
				eq(f0old, f1old)
				print('#', name)
				for i in range(0, len(data), 16):
					print('FW+0x%x:' % (addr+i), hexdump(f0old[i:i+16]), '->', hexdump(data[i:i+16]))
				print()

if __name__ == '__main__':
	main()
