#!/usr/bin/python3

import sys, io, struct, collections

from util import *

GUID_FMP = b'\xed\xd5\xcb\x6d\x2d\xe8\x44\x4c\xbd\xa1\x71\x94\x19\x9a\xd9\x2a'

FWType = collections.namedtuple('FWType', ['crcsize', 'dest', 'x'])

SAM_FW_TYPES = {
	b'\x3c\x52\x1a\xb2\xc5\xa0\x33\x46\xa4\xef\xd5\x7f\x39\x98\x7f\xeb': FWType(16,  0, 0x2e), # SP7
	b'\xdd\xe8\x5c\x85\x80\x57\x65\x40\x95\x80\xe4\xd0\xc0\x1d\x07\xcc': FWType(16,  0, 0x3a), # SP7+
	b'\x0f\xcb\x2c\x88\x1d\x71\x2c\x40\xa7\xc4\x88\x3c\x78\x00\x23\x0e': FWType(16, 16, 0x42), # SP8
	b'\x7b\x09\xe2\x72\x83\x11\xd2\x41\x8f\xa2\xa2\xcb\xa7\x50\x15\x84': FWType(32, 16, 0x5d), # SP9
}

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
	print('Update type GUID:', hexdump(UpdateImageTypeId))
	fwtype = SAM_FW_TYPES[UpdateImageTypeId]
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
		_, _, dest, _, fwversion3, a, _, _, _, addr, _, valx = struct.unpack('<BBBBIBBBBBBH', setup)
		eq(dest, fwtype.dest)
		eq(fwversion3, fwversion)
		eq(a, 1)
		eq(addr, 0x04, 0x14)
		eq(valx, fwtype.x)
		data = []
		pos = 0
		for j in range(numrows):
			offset, n = r(f, 'IB')
			data.append(f.read(n))
			eq(offset, pos)
			pos += n
		data = b''.join(data)
		parse_fw(data, fwtype, fwversion)
		destfn = '%s.%i.img' % (fn, i)
		print('Writing to', destfn, '...')
		with open(destfn, 'wb') as out:
			out.write(setup)
			out.write(data)
	# EOF
	eq(f.read(1), b'')

def parse_fw(buf, fwtype, fwversion):
	print('Size:', hex(len(buf)))
	with io.BytesIO(buf) as f:
		# Header 1
		h1size, h1type, a, h2pos, fwpos = r(f, '5I')
		eq(h1type, 1)
		eq(h1size, 0x14)
		# Header 2
		f.seek(h2pos)
		h2size, h2type, a, b, valx, dest, fwversion4, zero0, h3pos, flags, zero1, h4pos = r(f, '12I')
		eq(h2type, 2)
		eq(h2size, 0x30)
		eq(b, 4)
		eq(valx, fwtype.x)
		eq(dest, fwtype.dest)
		eq(fwversion4, fwversion)
		print('Flags:', hex(flags))
		# Header 3
		f.seek(h3pos)
		h3size, h3type, a, h3count = r(f, '4I')
		eq(h3type, 3)
		eq(h3size, 0x24)
		for i in range(h3count):
			a, flag, start, addr, size = r(f, '5I')
			eq(flag & 1, 1)
			print('Flash data %i at 0x%x, 0x%x bytes, dest addr 0x%08x' % (i, start, size, addr))
		# Header 4
		f.seek(h4pos)
		h4size, h4type, a, b, c, d = r(f, '6I')
		eq(h4type, 4)
		eq(h4size, 0x18)
		# Data
		if fwtype.crcsize == 16:
			crc, = struct.unpack('<H', buf[-2:])
			crccalc = crc16(buf[fwpos:-2])
		elif fwtype.crcsize == 32:
			crc, = struct.unpack('<I', buf[-4:])
			crccalc = crc32(buf[fwpos:-4])
		eq(crccalc, crc)


if __name__ == '__main__':
	_, fn = sys.argv
	with open(fn, 'rb') as f:
		parse_fmp(f)
	print()
	print('Done!')

