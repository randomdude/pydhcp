import unittest
import binascii

import dhcp


class TestOptionParsing(unittest.TestCase):

    def test_parsing_general(self):

	# Bytes taken from real DHCP request, decoding verified against wireshark
        rawbytes = "\x35\x01\x01\x3d\x07\x01" \
"\x00\x50\x56\x10\x64\xc8\x32\x04\xc0\xa8\x64\xc8\x39\x02\x02\x40" \
"\x37\x07\x01\x03\x06\x0c\x0f\x1c\x2a\x3c\x0c\x75\x64\x68\x63\x70" \
"\x20\x31\x2e\x32\x37\x2e\x32\x0c\x0b\x62\x6f\x6f\x74\x32\x64\x6f" \
"\x63\x6b\x65\x72\xff\x00"
        parsed = dhcp.DhcpOptions(options=rawbytes)

        assert(parsed.operation == ['\x01'])
        assert(parsed.client_id == ['\x00\x50\x56\x10\x64\xc8'])
#	todo: test parameter_request options
        assert(parsed.hostname == ['boot2docker'])

if __name__ == '__main__':
    unittest.main()
