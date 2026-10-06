"""cnmm anti-bot token provider.

The generation algorithm is NOT reconstructed yet (it lives in libil2cpp.so,
referenced from the string literal at 0x5F9B488). Implement a provider with
`__call__(command: str, params: dict) -> bytes` (31 bytes) and pass it to
Client. Until then `ReplayCnmm` can only reuse captured values, which the
server will most likely reject because bytes 1-3 and 28-30 vary.
"""

CNMM_LEN = 31


class ReplayCnmm:
    """Placeholder: returns a fixed captured token (for protocol plumbing tests)."""
    def __init__(self, token_hex):
        self.token = bytes.fromhex(token_hex)
        assert len(self.token) == CNMM_LEN

    def __call__(self, command, params):
        return self.token


def xor_diff(a_hex, b_hex):
    """Helper for analysing captured tokens: per-byte XOR of two cnmm values."""
    a, b = bytes.fromhex(a_hex), bytes.fromhex(b_hex)
    return bytes(x ^ y for x, y in zip(a, b)).hex()
