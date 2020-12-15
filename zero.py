from Crypto.Cipher import AES
from os import urandom


def genBytes(num: int) -> bytes:
	# Generate 8 bytes data

	if (num == 0):
		nonce = b'\x00' * 8

	else:
		# Random nonce
		nonce = urandom(8)

	return nonce


def main() -> int:
	# Send client challenge to AD
	clientChallenge = genBytes(0)

	# Send server challenge to AD
	serverChallenge = genBytes(1)

	# Generate 32 bytes session key (from secret key in practice)
	sessionKey = urandom(32)

	# Initialization Vector (NULL in default)
	# iv = urandom(16)
	iv = b'\x00' * 16

	# Generate client credential with session key
	# (Encrypto client challenge with AES)
	clientCiphar = AES.new(sessionKey, AES.MODE_CFB, iv=iv)
	clientCredential = clientCiphar.encrypt(clientChallenge)

	# Override with zero
	clientCredential = b'\x00' * 8

	# Generate server credential with session key
	# (Encrypto server challenge with AES)
	serverCiphar = AES.new(sessionKey, AES.MODE_CFB, iv=iv)
	serverCredential = serverCiphar.encrypt(serverChallenge)

	# Decripto client credential with
	serverCiphar2 = AES.new(sessionKey, AES.MODE_CFB, iv=iv)
	decriptedClientCredential = serverCiphar2.decrypt(clientCredential)
	# decriptedClientCredential = b'\x00' * 8

	# Compare client challenge with encripted client credential
	if (clientChallenge == decriptedClientCredential):
		num = 1
	else:
		num = 0

	return num


if __name__ == "__main__":
	count = 0
	roop = 100000

	for i in range(roop):
		print("\r[{}/{}]".format(i+1, roop), end='')
		count += main()

	print("\n\n--<Result>------------------------------------")
	print("  Count\t:\t{}/{}".format(count, roop))
	try:
		print("  Probs\t:\t{}   \t({}%)".format((count / roop), ((100 * count) / roop)))
	except ZeroDivisionError as e:
		print(e)
	print("  1/256\t:\t{}\t({}%)".format(1/256, 100/256))
