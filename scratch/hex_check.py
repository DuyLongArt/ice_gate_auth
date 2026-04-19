import base64
import uuid

# Hex ID from logs
id_hex = "fb3148e46ccb471f97fa03d910dc4c82"
id_bytes = bytes.fromhex(id_hex)

print(f"Hex: {id_hex}")
print(f"UUID: {uuid.UUID(hex=id_hex)}")
print(f"Base64: {base64.b64encode(id_bytes).decode()}")
print(f"Base64URL: {base64.urlsafe_b64encode(id_bytes).decode().rstrip('=')}")

# Handle ID (Hex) from logs: 2d7a464935477a4c52782d582d67505a454e784d6767
handle_hex = "2d7a464935477a4c52782d582d67505a454e784d6767"
handle_str = bytes.fromhex(handle_hex).decode()
print(f"Handle String: {handle_str}")
