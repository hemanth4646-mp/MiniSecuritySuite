from cryptography.fernet import Fernet
from pathlib import Path
from utils import setup_logging

log = setup_logging(__name__)

KEY_FILE = Path(__file__).with_name("secret.key")


def load_or_create_key(path: Path = KEY_FILE) -> bytes:
	if path.exists():
		return path.read_bytes()
	k = Fernet.generate_key()
	path.write_bytes(k)
	return k


def run_encryption_tool():
	key = load_or_create_key()
	log.info("Encryption key loaded successfully")
	c = Fernet(key)
	m = input("Message: ")
	b = m.encode() if not isinstance(m, bytes) else m
	e = c.encrypt(b)
	log.info("Encrypted: %s", e)
	d = c.decrypt(e).decode()
	log.info("Decrypted: %s", d)


if __name__ == "__main__":
	run_encryption_tool()
