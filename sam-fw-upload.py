#!/usr/bin/python3

import sys, struct

from util import *

sys.path.insert(1, '../surface-aggregator-module/scripts/ssam/')
import libssam

debug = True

def cmd(ctrl, tc, cid, data, hasresp):
	print('TC %02x CID %02x:' % (tc, cid), hexdump(data) if data else None)
	req = libssam.Request(tc, 1, cid, 0, libssam.REQUEST_HAS_RESPONSE if hasresp else 0, data)
	resp = ctrl.request(req)
	print('\t=>', hexdump(resp) if resp else None)
	return resp

def upload(fn):
	if fn:
		with open(fn, 'rb') as f:
			setup = f.read(16)
			_, _, dest, _, newver, a, _, _, _, addr, _, val2e = struct.unpack('<BBBBIBBBBBBH', setup)
			eq(dest, 0)
			eq(a, 1)
			eq(addr, 0x04, 0x14)
			eq(val2e, 0x2e)
			print('New firmware version:', fw_version_str(newver))
			data = f.read()
	with libssam.Controller() as c:
		if debug:
			# set debug target = host
			cmd(c, 7, 0x4b, b'\1', False)
			# enable debug mode = 2
			cmd(c, 7, 0x4e, b'\2', False)
		# disable safe mode
		cmd(c, 7, 0x5f, b'\0', False)
		# read cur fw version
		resp = cmd(c, 1, 0x13, None, True)
		curver, = struct.unpack('<I', resp)
		print('Current firmware version:', fw_version_str(curver))
		# read cur fw location
		resp = cmd(c, 1, 0x2e, None, True)
		fwloc, zero1, val2e, zero2 = struct.unpack('<BBHI', resp)
		eq(fwloc, 0x11, 0x12)
		eq(zero1, 0)
		eq(val2e, 0x2e)
		eq(zero2, 0)
		if fn and ((addr == 0x04) == (fwloc == 0x11)): raise Exception('cannot flash active firmware location!')
		# read flash status
		resp = cmd(c, 9, 2, None, True)
		count, zero1, zero2, four = struct.unpack_from('<4B', resp)
		for i in range(count):
			version, fwloc2, fwid, val2e = struct.unpack('<IBBH', resp[4+i*8:4+(i+1)*8])
			print('FW 0x%02x 0x%x, loc/flags 0x%02x, version 0x%08x = %s' % (fwid, val2e, fwloc2, version, fw_version_str(version)))
		if not fn: return
		# upload setup header
		resp = cmd(c, 9, 3, setup, True)
		# upload firmware
		blksize = 16
		numblk = (len(data) - 1) // blksize + 1
		for i in range(numblk):
			flags = 0
			if i == 0: flags |= 0x80
			if i == numblk-1: flags |= 0x40
			d = data[i*blksize:(i+1)*blksize]
			cookie = 0x1234 ^ i
			resp = cmd(c, 9, 4, struct.pack('<BBHI', flags, len(d), cookie, i*blksize) + d, True)
			cookieresp, status = struct.unpack_from('<HB', resp)
			eq(cookieresp, cookie)
			eq(status, 0)

if __name__ == '__main__':
	if len(sys.argv) == 1: fn = None
	elif len(sys.argv) == 2: _, fn = sys.argv
	else: raise Exception('invalid args')
	upload(fn)
	print('Done!')

