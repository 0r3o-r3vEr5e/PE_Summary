import textwrap

def xor(data, key):
	return bytearray( ((data[i] ^ key[i % len(key)]) for i in range(0, len(data))) )

def rev_endiannes(data):
	tmp = [data[i:i+8] for i in range(0, len(data), 8)]
	
	for i in range(len(tmp)):
		tmp[i] = "".join(reversed([tmp[i][x:x+2] for x in range(0, len(tmp[i]), 2)]))
	
	return "".join(tmp)

data = bytearray.fromhex("882B04D3CC4A6A80CC4A6A80CC4A6A8087326981C84A6A8087326E81DB4A6A8087326F81CB4A6A8087326B81DF4A6A80CC4A6B80044A6A8087326281DC4A6A8087329580CD4A6A8087326881CD4A6A8052696368CC4A6A80")
key  = bytearray.fromhex("CC4A6A80")

rch_hdr = (xor(data,key)).hex()
rch_hdr = textwrap.wrap(rch_hdr, 16)

for i in range(2,len(rch_hdr)):
	tmp = textwrap.wrap(rch_hdr[i], 8)
	f1 = rev_endiannes(tmp[0])
	f2 = rev_endiannes(tmp[1])
	print("{} {} : {}.{}.{}".format(f1, f2, str(int(f1[4:],16)), str(int(f1[0:4],16)), str(int(f2,16)) ))