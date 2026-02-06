#!/usr/bin/env python

# Copyright (c) 2010, Rich Wareham <richwareham@gmail.com>
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import hashlib
import io
import json
import string
import random
import sys

from optparse import OptionParser

MASTER_KEY_SRC = 'master-key.txt'

def main():
	"""The main body of the program."""

	parser = OptionParser()

	parser.add_option('-m', '--master', dest='master_key_file',
		help='load master key from FILE', metavar='FILE',
		default='master-key.txt')
	
	parser.add_option('-k', '--sink', action='store_true', 
		dest='gen_sink', default=False, 
		help='generate a sink key rather than a source key')
	
	parser.add_option('', '--ksv', dest='ksv',
		help='use a specific KSV expressed in hexadecimal',
		metavar='KSV', default=None)
	
	parser.add_option('-j', '--json', action='store_true', 
		dest='output_json', default=False, 
		help='output key and KSV as JSON')

	parser.add_option('-b', '--bin', dest='output_bin',
		help='output key and KSV to a binary FILE (use "-" for stdout)',
		metavar='FILE', default=None)

	parser.add_option('-n', '--count', dest='bin_count',
		help='number of keys to generate for binary output',
		metavar='COUNT', default='1')

	parser.add_option('', '--bin-out', dest='bin_output_name',
		help='output file name for binary output (overrides --bin)',
		metavar='FILE', default=None)
	
	parser.add_option('-t', '--test', action='store_true', 
		dest='do_test', default=False, 
		help='generate source and sink keys and test they work')

	(options, args) = parser.parse_args()

	# read the master key file
	key_matrix = read_key_file(open(options.master_key_file))

	# if asked to do a test, do one and exit
	if options.do_test:
		do_test(key_matrix)
		return

	bin_count = int(options.bin_count)
	output_bin_path = options.bin_output_name or options.output_bin

	if bin_count < 1:
		parser.error('count must be >= 1')

	if bin_count > 1 and options.ksv is not None:
		parser.error('count > 1 cannot be combined with --ksv')

	if bin_count > 1 and not output_bin_path:
		parser.error('count > 1 requires --bin or --bin-out')

	# generate a ksv if necessary
	if options.ksv is not None:
		ksv = int(options.ksv, 16)
	else:
		ksv = gen_ksv()

	# generate a key
	if options.gen_sink:
		key = gen_sink_key(ksv, key_matrix)
	else:
		key = gen_source_key(ksv, key_matrix)

	# output the key
	if output_bin_path:
		if bin_count > 1:
			output_bin_batch(bin_count, key_matrix, options.gen_sink, output_bin_path)
		else:
			output_bin_single(ksv, key, output_bin_path)
	elif options.output_json:
		output_json(ksv, key, options.gen_sink)
	else:
		output_human_readable(ksv, key, options.gen_sink)

def do_test(key_matrix):
	"""Perform a self-test.

	Generate both a source key and sink key with random (different) KSVs
	and test that the HDCP shared-key system works."""

	print('Performing self test.')

	# generate source key
	src_ksv = gen_ksv() 
	src_key = gen_source_key(src_ksv, key_matrix)
	output_human_readable(src_ksv, src_key, False)

	print('')

	# generate sink key
	snk_ksv = gen_ksv() 
	snk_key = gen_sink_key(snk_ksv, key_matrix)
	output_human_readable(snk_ksv, snk_key, True)

	# add sink keys together according to src ksv
	key1 = sum( x[1] for x in zip(range(40), snk_key) if src_ksv & (1<<x[0]) ) & 0xffffffffffffff

	# add source keys together according to sink ksv
	key2 = sum( x[1] for x in zip(range(40), src_key) if snk_ksv & (1<<x[0]) ) & 0xffffffffffffff

	print('\nGenerated keys: sink = %014x, source = %014x' % (key1, key2))

	if key1 == key2:
		print('Test PASSED')
	else:
		print('Test FAILED')

def read_key_file(filelike):
	"""Read a HDCP master key from a key file.

	The key file is formatted into 40*40 56-bit hex values separated by
	white space. The first 40 values correspond to row 1 of the matrix, the
	next 40 row 2, etc. Lines beginning with a '#' are ignored. """

	key_matrix = [ [] ]

	for line in filelike:
		if line[0] == '#':
			# This is a comment... skip
			continue

		# split the line into words and parse the hex
		for entry in map(lambda x: int(x, 16), string.split(line)):
			# do we need to start a new row?
			if len(key_matrix[-1]) >= 40:
				key_matrix.append([])

			# append this entry to the row
			key_matrix[-1].append(entry)

	# check we read the right number of entries in total
	assert( len(key_matrix) == 40 )
	assert( len(key_matrix[-1]) == 40 )

	return key_matrix

def transpose(matrix):
	"""Transpose a master key matrix.

	This returns a copy of matrix which has been transposed."""

	return zip(*matrix)

def gen_ksv():
	"""Generate a KSV.

	A KSV is a forty-bit number that (in binary) consists of twenty ones
	and twenty zeroes"""

	# generate KSV - 20 1s and 20 0s
	ksv = (['1'] * 20) + (['0'] * 20)

	# permute KSV
	random.shuffle(ksv)

	# convert the binary to int
	return int(string.join(ksv, ''), 2)

def gen_source_key(ksv, key_matrix):
	"""Generate a source key from the master key matrix passed.

	To generate a source key, take a forty-bit number that (in binary)
	consists of twenty ones and twenty zeroes; this is the source KSV.  Add
	together those twenty rows of the matrix that correspond to the ones in
	the KSV (with the lowest bit in the KSV corresponding to the first
	row), taking all elements modulo two to the power of fifty-six; this is
	the source private key."""

	# generate a list of bits for the KSV starting with the LSB
	ksv_bits = ( (ksv >> x) & 1 for x in range(40) )

	# zip the master key matrix and the ksv s.t. the LSB of KSV is associated with
	# the first row, etc. Then filter to only select those rows where the
	# appropriate bit of the KSV is 1.
	master_rows = ( x[1] for x in zip(ksv_bits, key_matrix) if x[0] == 1 )

	# now generate the key
	key = [0] * 40

	for row in master_rows:
		# add row to key
		key = [ (x[0] + x[1]) & 0xffffffffffffff for x in zip(key, row) ]

	return tuple(key)

def gen_sink_key(ksv, key_matrix):
	"""Generate a sink key from the master key matrix passed.

	To generate a sink key, do the same as for a source key but the
	transposed master matrix."""

	return gen_source_key(ksv, transpose(key_matrix))

def output_human_readable(ksv, key, is_sink):
	"""Print a human readable version of the KSV and key.

	The KSV is a single integer. The key is a list of 40 integers."""

	# output the ksv
	print('KSV: %010x' % ksv)

	# output the key
	key_strs = [ '%014x' % x for x in key ]

	print('\n%s Key:' % ('Sink' if is_sink else 'Source'))
	for idx in range(0, 40, 5):
		print(string.join(key_strs[idx:idx+5], ' '))

def output_json(ksv, key, is_sink):
	"""Print a JSON version of the KSV and key.

	The KSV is a single integer. The key is a list of 40 integers."""

	print(json.dumps( {
		'ksv': ('%010x' % ksv), 
		'key': [ '%014x' % x for x in key ],
		'type': 'sink' if is_sink else 'source' },
		sort_keys=True, indent=True))

def build_bin_record(ksv, key):
	ksv_bytes = int_to_bytes(ksv, 5, 'little')
	key_bytes = b''.join(int_to_bytes(x, 7, 'little') for x in key)
	payload = ksv_bytes + b'\x00\x00\x00' + key_bytes
	digest = hashlib.sha1(payload).digest()
	return payload + digest

def int_to_bytes(value, length, byteorder):
	result = []
	for _ in range(length):
		result.append(value & 0xff)
		value >>= 8
	if byteorder == 'big':
		result.reverse()
	return bytes(bytearray(result))

def open_binary_stream(output_path):
	if output_path == '-':
		return io.open(sys.stdout.fileno(), 'wb', closefd=False)
	return open(output_path, 'wb')

def output_bin_single(ksv, key, output_path):
	"""Write a single key in binary format.

	Format: 01 00 00 00 + KSV (5 bytes) + 00 00 00 + key data (280 bytes)
	+ SHA-1 (20 bytes).
	"""

	record = build_bin_record(ksv, key)
	stream = open_binary_stream(output_path)
	try:
		stream.write(b'\x01\x00\x00\x00' + record)
	finally:
		if output_path != '-':
			stream.close()

def output_bin_batch(count, key_matrix, is_sink, output_path):
	"""Write multiple keys in binary format.

	Format: 01 00 00 00 + (KSV + 00 00 00 + key data + SHA-1) * count
	"""

	stream = open_binary_stream(output_path)
	try:
		stream.write(b'\x01\x00\x00\x00')
		for _ in range(count):
			ksv = gen_ksv()
			key = gen_sink_key(ksv, key_matrix) if is_sink else gen_source_key(ksv, key_matrix)
			stream.write(build_bin_record(ksv, key))
	finally:
		if output_path != '-':
			stream.close()

# run the 'main' function if this file is being executed directly
if __name__ == '__main__':
	main()
