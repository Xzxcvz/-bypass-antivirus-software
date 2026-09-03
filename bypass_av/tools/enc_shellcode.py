#!/usr/bin/env python3
import sys

data = open('shellcode.bin', 'rb').read()
k = 0xCE
enc = bytes([(b ^ k ^ ((i*0x13+0x57)&0xFF)) & 0xFF for i,b in enumerate(data)])

h = 'const BYTE g_shellcode_enc[] = {\n'
for i in range(0, len(enc), 12):
    h += '    ' + ', '.join(f'0x{b:02X}' for b in enc[i:i+12]) + ',\n'
h += '};\nconst SIZE_T g_shellcode_enc_len = ' + str(len(enc)) + ';\n'

open('shellcode_data.h', 'w').write(h)
print('OK size:', len(enc))
