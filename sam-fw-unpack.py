#!/usr/bin/python3

import sys, io, struct, collections

from util import *

GUID_FMP = b'\xed\xd5\xcb\x6d\x2d\xe8\x44\x4c\xbd\xa1\x71\x94\x19\x9a\xd9\x2a'

FWType = collections.namedtuple('FWType', ['crcsize', 'dest', 'device'])

SAM_FW_TYPES = {
	b'\xe4\xd3\x74\x07\x4d\x98\xae\x41\xbe\xb5\x44\x3f\xa7\x28\x15\x11': FWType(16, None, None), # SP4
	b'\x98\xcd\x24\x36\xb6\xbd\x1b\x46\x84\xa3\x4f\x48\x53\xef\xc7\xe3': FWType(16, None, None), # SP5/SP6
	b'\xcb\xfb\xa9\x53\xca\x9a\xe3\x46\xb9\x08\x95\x1c\x34\xeb\xba\xc4': FWType(16,    0, 0x2d), # SPX
	b'\x3c\x52\x1a\xb2\xc5\xa0\x33\x46\xa4\xef\xd5\x7f\x39\x98\x7f\xeb': FWType(16,    0, 0x2e), # SP7
	b'\xdd\xe8\x5c\x85\x80\x57\x65\x40\x95\x80\xe4\xd0\xc0\x1d\x07\xcc': FWType(16,    0, 0x3a), # SP7+
	b'\x0f\xcb\x2c\x88\x1d\x71\x2c\x40\xa7\xc4\x88\x3c\x78\x00\x23\x0e': FWType(16,   16, 0x42), # SP8
	b'\x7b\x09\xe2\x72\x83\x11\xd2\x41\x8f\xa2\xa2\xcb\xa7\x50\x15\x84': FWType(32,   16, 0x5d), # SP9
	b'\x3a\x80\xd2\xec\x01\x35\xba\x4c\xe2\x1c\xf6\xbb\x1b\x34\xaa\x20': FWType(16, None, None), # SB
	b'\x3d\x9c\xda\x37\x50\x6b\xbf\x4d\x82\xb8\x46\xca\x91\x2d\x98\xf2': FWType(16, None, None), # SB2
	b'\xba\x12\x0d\x48\x5b\x2a\xe2\x40\x8b\x1f\x9f\x32\xd0\x6a\x8f\xb2': FWType(16,    0, 0x25), # SB3
	b'\x63\xef\xd1\x53\xc2\x84\xa2\x4f\xbb\x99\xb5\x87\x2b\xde\x6d\x36': FWType(16, None, None), # SL/SL2
	b'\xd6\x29\x5e\x4f\xdc\x0e\x14\x4b\x9f\x48\x7e\x9d\x02\xf7\xd2\x13': FWType(16,    0, 0x24), # SL3I
	b'\xf6\x18\x67\x16\x2e\x65\x34\x47\x88\x21\x6c\xe6\x39\x94\xbb\xb8': FWType(16,    0, 0x2c), # SL3A
	b'\xcd\xb1\x65\xee\x00\xe5\x37\x45\xbe\xc0\x71\x32\x37\xc2\xbb\x70': FWType(16,    0, 0x3d), # SL4I
	b'\xcc\x8b\x37\x46\x44\xb4\x1e\x45\x84\x65\x53\x01\x54\xb2\xa8\x80': FWType(16,    0, 0x37), # SL4A
	b'\x8a\x71\x35\x9b\x0a\x63\xd7\x4b\xb6\xf2\x9f\x4c\x21\xed\x88\x2e': FWType(32,   16, 0x63), # SL5
	b'\x98\x68\xef\x52\xd3\xde\xbc\x40\xa1\xee\x36\xcc\x04\x59\xb1\xd4': FWType(16,    0, 0x39), # SLGo
	b'\xae\x3d\xd1\xd2\x0c\xee\x58\x49\xa5\x25\x0c\x81\x5c\xe4\x4a\x90': FWType(16,    0, 0x4f), # SLGo2
	b'\x55\x49\x51\xa7\x19\x33\x9b\x4e\x92\x85\xff\x5a\xe2\xde\x3c\x87': FWType(16,    0, 0x3c), # SLS
	b'\xf5\x4d\x70\x81\x95\x97\xbc\x41\x93\x42\xce\xfb\x2e\xa4\x3c\xff': FWType(16, None, None), # SS2
	b'\x51\xf2\x13\x28\x5d\xc3\x50\x43\xb7\xd6\x1d\xdd\xc3\x27\x7f\x96': FWType(16,   16, 0x60), # SS2+
	b'\x9d\xbf\xd2\x30\x2d\xe7\x8b\x48\xaa\xd1\x4f\x26\xde\xff\x4a\x97': FWType(16, None, None), # SH2S
}

def check_crc(fwtype, buf):
	if fwtype.crcsize == 16:
		crc, = struct.unpack('<H', buf[-2:])
		crccalc = crc16(buf[:-2])
	elif fwtype.crcsize == 32:
		crc, = struct.unpack('<I', buf[-4:])
		crccalc = crc32(buf[:-4])
	eq(crccalc, crc)

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
	parse_sam(f, fwtype)
	# EOF
	eq(f.read(1), b'')

def parse_sam(f, fwtype):
	MSS1, a, fwversion, minfwversion = r(f, '4sIII')
	eq(MSS1, b'MSS1')
	eq(a, 0x10) # HeaderSize?
	print('SAM firmware version', hex(fwversion), '=', fw_version_str(fwversion))
	SAM, samver, hdrsize = r(f, '4sBB')
	if SAM == b'SAMH' and samver == 1:
		# old format, SP4/SB only, single image
		eq(hdrsize, 0x10)
		numrows, combinedsize, fwversion2 = r(f, 'HII')
		eq(fwversion2, fwversion)
		print()
		print('Reading firmware image')
		data = []
		pos = None
		for j in range(numrows):
			offset, n = r(f, 'IB')
			if pos is None:
				print('Origin:', hex(offset))
				pos = offset
			eq(offset, pos)
			data.append(f.read(n))
			pos += n
		data = b''.join(data)
		destfn = '%s.%i.img' % (fn, 0)
		print('Writing to', destfn, '...')
		with open(destfn, 'wb') as out:
			out.write(data)
	elif SAM == b'SAML' and samver == 1:
		# format for SP5/SP6/SB2/SL/SL2/SS2/SH2S, two images, no additional headers
		eq(hdrsize, 0x10)
		numrows, combinedsize, fwversion2 = r(f, 'HII')
		eq(fwversion2, fwversion)
		for i in range(2):
			print()
			print('Reading firmware image', i)
			data = []
			pos = None
			for j in range(numrows // 2):
				offset, n = struct.unpack('>IH', f.read(6))
				if pos is None:
					print('Origin:', hex(offset))
					pos = offset
				elif offset > pos:
					print('Padding from', hex(pos), 'to', hex(offset))
					data.append((offset-pos) * b'\xff')
					pos = offset
				eq(offset, pos)
				data.append(f.read(n))
				pos += n
			data = b''.join(data)
			check_crc(fwtype, data)
			destfn = '%s.%i.img' % (fn, i)
			print('Writing to', destfn, '...')
			with open(destfn, 'wb') as out:
				out.write(data)
	elif SAM == b'SAML' and samver == 3:
		# newest format, two images: setup (0x10 bytes) + headers (0x66c bytes) + firmware
		eq(hdrsize, 0x19)
		a, b, c, numrows, combinedsize, fwversion2 = r(f, 'BIIHII')
		eq(fwversion2, fwversion)
		for i in range(2):
			setup = f.read(16)
			print()
			print('Reading firmware image', i)
			print('Setup data:', hexdump(setup))
			_, _, dest, _, fwversion3, a, _, _, _, addr, _, device = struct.unpack('<BBBBIBBBBBBH', setup)
			eq(dest, fwtype.dest)
			eq(fwversion3, fwversion)
			eq(a, 1, 3)
			eq(addr, 0x04, 0x14)
			eq(device, fwtype.device)
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
	else:
		raise Exception('unknown SAM FW encoding %r %i' % (SAM, samver))

def parse_fw(buf, fwtype, fwversion):
	print('Size:', hex(len(buf)))
	with io.BytesIO(buf) as f:
		# Header 1
		h1size, h1type, a, h2pos, fwpos = r(f, '5I')
		eq(h1type, 1)
		eq(h1size, 0x14)
		# Header 2
		f.seek(h2pos)
		h2size, h2type, a, b, device, dest, fwversion4, zero0, h3pos, flags, zero1, h4pos = r(f, '12I')
		eq(h2type, 2)
		eq(h2size, 0x30)
		eq(b, 4)
		eq(device, fwtype.device)
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
		check_crc(fwtype, buf[fwpos:])

if __name__ == '__main__':
	_, fn = sys.argv
	with open(fn, 'rb') as f:
		parse_fmp(f)
	print()
	print('Done!')

