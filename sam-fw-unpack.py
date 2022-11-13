#!/usr/bin/python3

import sys, io, struct

from util import *

GUID_FMP = b'\xed\xd5\xcb\x6d\x2d\xe8\x44\x4c\xbd\xa1\x71\x94\x19\x9a\xd9\x2a'
GUID_SAM = b'\x3c\x52\x1a\xb2\xc5\xa0\x33\x46\xa4\xef\xd5\x7f\x39\x98\x7f\xeb'

def parse_fmp(f):
	# EFI_CAPSULE_HEADER
	CapsuleGuid, HeaderSize, Flags, CapsuleImageSize = r(f, '16sIII')
	f.read(HeaderSize - 0x1c)
	eq(CapsuleGuid, GUID_FMP)
	# EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER
	Version, EmbeddedDriverCount, PayloadItemCount = r(f, 'IHH')
	eq(Version, 1)
	eq(EmbeddedDriverCount, 0)
	PayloadOffsets = [r(f, 'Q')[0] for _ in range(PayloadItemCount)]
	eq(PayloadOffsets, [0x10])
	# EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER
	Version, UpdateImageTypeId, UpdateImageIndex, _, UpdateImageSize, UpdateVendorCodeSize, UpdateHardwareInstance = r(f, 'I16sB3sIIQ')
	eq(Version, 2)
	eq(UpdateImageTypeId, GUID_SAM)
	# EFI_FIRMWARE_IMAGE_AUTHENTICATION
	MonotonicCount, CertificateLength, CertificateRevision, CertificateType, CertTypeGuid = r(f, 'QIHH16s')
	Certificate = f.read(CertificateLength - 0x18)
	# Payload
	MSS1, a, fwversion, b = r(f, '4sIII')
	eq(MSS1, b'MSS1')
	eq(a, 0x10) # HeaderSize?
	SAML, a, b, c, numrows, combinedsize, fwversion2 = r(f, '4s3sIIHII')
	eq(SAML, b'SAML')
	eq(fwversion2, fwversion)
	print('SAM firmware version', hex(fwversion), '=', fw_version_str(fwversion))
	for i in range(2):
		setup = f.read(16)
		print()
		print('Reading firmware image', i)
		print('Setup data:', hexdump(setup))
		_, _, dest, _, fwversion3, a, _, _, _, addr, _, val2e = struct.unpack('<BBBBIBBBBBBH', setup)
		eq(dest, 0)
		eq(fwversion3, fwversion)
		eq(a, 1)
		eq(addr, 0x04, 0x14)
		eq(val2e, 0x2e)
		data = []
		pos = 0
		for j in range(numrows):
			offset, n = r(f, 'IB')
			data.append(f.read(n))
			eq(offset, pos)
			pos += n
		data = b''.join(data)
		parse_fw(data, fwversion)
		destfn = '%s.%i.img' % (fn, i)
		print('Writing to', destfn, '...')
		with open(destfn, 'wb') as out:
			out.write(setup)
			out.write(data)
	# EOF
	eq(f.read(1), b'')

def parse_fw(buf, fwversion):
	print('Size:', hex(len(buf)))
	with io.BytesIO(buf) as f:
		# Header 1
		h1size, h1type, a, h2pos, fwpos = r(f, '5I')
		eq(h1type, 1)
		eq(h1size, 0x14)
		# Header 2
		f.seek(h2pos)
		h2size, h2type, a, b, val2e, dest, fwversion4, zero0, h3pos, flags, zero1, h4pos = r(f, '12I')
		eq(h2type, 2)
		eq(h2size, 0x30)
		eq(b, 4)
		eq(val2e, 0x2e)
		eq(dest, 0)
		eq(fwversion4, fwversion)
		print('Flags:', hex(flags))
		# Header 3
		f.seek(h3pos)
		h3size, h3type, a, h3count = r(f, '4I')
		eq(h3type, 3)
		eq(h3size, 0x24)
		for i in range(h3count):
			one, flag, start, addr, size = r(f, '5I')
			eq(one, 1)
			eq(flag & 1, 1)
			print('Flash data %i at 0x%x, 0x%x bytes, dest addr 0x%08x' % (i, start, size, addr))
		# Header 4
		f.seek(h4pos)
		h4size, h4type, a, b, c, d = r(f, '6I')
		eq(h4type, 4)
		eq(h4size, 0x18)
		# Data
		crc, = struct.unpack('<H', buf[-2:])
		crccalc = crc16(buf[fwpos:-2])
		eq(crccalc, crc)

if __name__ == '__main__':
	_, fn = sys.argv
	with open(fn, 'rb') as f:
		parse_fmp(f)
	print()
	print('Done!')

