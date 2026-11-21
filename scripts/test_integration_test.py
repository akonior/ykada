"""Hardware-free tests for the PIV reset guard in integration_test.py.

Run with: python3 -m unittest discover -s scripts
"""
import base64
import unittest

import integration_test as itest

SERIAL = "12345678"
PAYMENT_PK = bytes(range(32))
STAKE_PK = bytes(range(32, 64))
OTHER_PK = bytes(range(64, 96))

# CIP-19 test vectors: a testnet base address and the two public keys it is built from.
CIP19_ADDRESS = ("addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc"
                 "3sq835lu7drv2xwl2wywfgs68faae")
CIP19_PAYMENT_VK = "addr_vk1w0l2sr2zgfm26ztc6nl9xy8ghsk5sh6ldwemlpmp9xylzy4dtf7st80zhd"
CIP19_STAKE_VK = "stake_vk1px4j0r2fk7ux5p23shz8f3y5y2qam7s954rgf3lg5merqcj6aetsft99wu"
CIP19_ENTERPRISE = "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz"


def address_of(payment_pk, stake_pk):
    """A testnet base address for two public keys, bech32-encoded."""
    payload = b"\x00" + itest.key_hash(payment_pk) + itest.key_hash(stake_pk)
    bits = "".join(f"{b:08b}" for b in payload)
    bits += "0" * (-len(bits) % 5)
    values = [int(bits[i:i + 5], 2) for i in range(0, len(bits), 5)]
    poly = itest.bech32_polymod(itest.bech32_hrp_expand("addr_test") + values + [0] * 6) ^ 1
    checksum = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
    return "addr_test1" + "".join(itest.BECH32[v] for v in values + checksum)


TEST_ADDRESS = address_of(PAYMENT_PK, STAKE_PK)


def pem(public_key):
    body = base64.b64encode(itest.ED25519_SPKI + public_key).decode()
    return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"


class FakeYkman:
    """Answers ykman like a set of YubiKeys would, and records every command."""

    def __init__(self, keys, serials=(SERIAL,), info_failures=(), exports=None):
        self.keys = keys  # slot -> raw Ed25519 public key
        self.serials = serials
        self.info_failures = dict(info_failures)  # slot -> (exit code, stderr)
        self.exports = exports or {}  # slot -> raw ykman stdout, to override the PEM
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        if args == ("ykman", "list"):
            return 0, "".join(f"YubiKey 5 (5.7.4) Serial: {s}\n" for s in self.serials), ""
        if args == ("ykman", "list", "--serials"):
            return 0, "".join(f"{s}\n" for s in self.serials), ""
        device, command = args[1:3], args[3:]
        if args[0] != "ykman" or device != ("--device", SERIAL):
            raise AssertionError(f"unexpected command {args}")
        if command[:3] == ("piv", "keys", "info"):
            return self.info(command[3])
        if command[:3] == ("piv", "keys", "export") and command[4:] == ("-",):
            return self.export(command[3])
        if command == ("piv", "reset", "--force"):
            return 0, "", ""
        raise AssertionError(f"unexpected command {args}")

    def info(self, slot):
        if slot in self.info_failures:
            code, err = self.info_failures[slot]
            return code, "", err
        if slot in self.keys:
            return 0, f"Key slot: {slot.upper()}\nAlgorithm: ED25519\nOrigin: IMPORTED\n", ""
        return 1, "", f"ERROR: {itest.NO_KEY} {slot.upper()}.\n"

    def export(self, slot):
        if slot in self.exports:
            return 0, self.exports[slot], ""
        if slot in self.keys:
            return 0, pem(self.keys[slot]), ""
        return 1, "", f"ERROR: {itest.NO_KEY} {slot.upper()}.\n"

    def reset_calls(self):
        return [call for call in self.calls if "reset" in call]


WALLET = {"9c": PAYMENT_PK, "9d": STAKE_PK}


class ResetAllowed(unittest.TestCase):
    def test_an_empty_yubikey_is_reset(self):
        ykman = FakeYkman({})
        self.assertEqual(itest.reset_piv(ykman, TEST_ADDRESS), SERIAL)
        self.assertEqual(ykman.reset_calls(), [("ykman", "--device", SERIAL, "piv", "reset", "--force")])

    def test_a_yubikey_with_only_the_test_wallet_is_reset(self):
        ykman = FakeYkman(WALLET)
        self.assertEqual(itest.reset_piv(ykman, TEST_ADDRESS), SERIAL)
        self.assertEqual(len(ykman.reset_calls()), 1)

    def test_every_key_slot_is_inspected_before_the_reset(self):
        ykman = FakeYkman(WALLET)
        itest.reset_piv(ykman, TEST_ADDRESS)
        inspected = [call[-1] for call in ykman.calls if call[3:6] == ("piv", "keys", "info")]
        self.assertEqual(inspected, itest.KEY_SLOTS)
        self.assertEqual(len(itest.KEY_SLOTS), 24)
        self.assertEqual(ykman.calls[-1][3:], ("piv", "reset", "--force"))


class ResetIsRefused(unittest.TestCase):
    def assert_not_reset(self, ykman, address=TEST_ADDRESS, reason=""):
        with self.assertRaises(itest.ResetRefused) as refused:
            itest.reset_piv(ykman, address)
        self.assertIn(reason, str(refused.exception))
        self.assertEqual(ykman.reset_calls(), [])

    def test_partial_wallet_payment_key_only(self):
        self.assert_not_reset(FakeYkman({"9c": PAYMENT_PK}), reason="only slot 9c")

    def test_partial_wallet_stake_key_only(self):
        self.assert_not_reset(FakeYkman({"9d": STAKE_PK}), reason="only slot 9d")

    def test_unrelated_key_without_a_wallet(self):
        self.assert_not_reset(FakeYkman({"9a": OTHER_PK}), reason="slot 9a")

    def test_test_wallet_plus_an_unrelated_key(self):
        for slot in ("9a", "9e", "82", "95"):
            with self.subTest(slot=slot):
                self.assert_not_reset(FakeYkman({**WALLET, slot: OTHER_PK}), reason=f"slot {slot}")

    def test_a_different_wallet_in_9c_and_9d(self):
        self.assert_not_reset(FakeYkman({"9c": PAYMENT_PK, "9d": OTHER_PK}),
                              reason="not the wallet in YKADA_ADDRESS")

    def test_wallet_keys_in_swapped_slots(self):
        self.assert_not_reset(FakeYkman({"9c": STAKE_PK, "9d": PAYMENT_PK}),
                              reason="not the wallet in YKADA_ADDRESS")

    def test_metadata_read_error(self):
        ykman = FakeYkman(WALLET, info_failures={"9e": (1, "ERROR: Unable to read metadata.\n")})
        self.assert_not_reset(ykman, reason="slot 9e")

    def test_unexpected_exit_code_even_with_the_no_key_message(self):
        ykman = FakeYkman({}, info_failures={"9a": (2, f"ERROR: {itest.NO_KEY} 9A.\n")})
        self.assert_not_reset(ykman, reason="slot 9a")

    def test_ykman_did_not_run(self):
        ykman = FakeYkman({}, info_failures={"82": (None, "timed out")})
        self.assert_not_reset(ykman, reason="slot 82")

    def test_public_key_that_is_not_ed25519(self):
        ykman = FakeYkman(WALLET, exports={"9c": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZI\n-----END"})
        self.assert_not_reset(ykman, reason="slot 9c")

    def test_no_yubikey(self):
        self.assert_not_reset(FakeYkman({}, serials=()), reason="0 YubiKeys")

    def test_two_yubikeys(self):
        self.assert_not_reset(FakeYkman({}, serials=(SERIAL, "87654321")), reason="2 YubiKeys")

    def test_address_with_a_bad_checksum(self):
        broken = TEST_ADDRESS[:-1] + ("q" if TEST_ADDRESS[-1] != "q" else "p")
        self.assert_not_reset(FakeYkman(WALLET), address=broken, reason="bad checksum")

    def test_address_without_a_stake_key(self):
        self.assert_not_reset(FakeYkman(WALLET), address=CIP19_ENTERPRISE,
                              reason="not a base address")


class AddressDecoding(unittest.TestCase):
    def test_cip19_address_holds_the_hashes_of_its_keys(self):
        payment_pk, stake_pk = (itest.bech32_payload(vk) for vk in (CIP19_PAYMENT_VK, CIP19_STAKE_VK))
        self.assertEqual(itest.wallet_key_hashes(CIP19_ADDRESS),
                         (itest.key_hash(payment_pk), itest.key_hash(stake_pk)))

    def test_cip19_wallet_may_be_reset(self):
        payment_pk, stake_pk = (itest.bech32_payload(vk) for vk in (CIP19_PAYMENT_VK, CIP19_STAKE_VK))
        ykman = FakeYkman({"9c": payment_pk, "9d": stake_pk})
        self.assertEqual(itest.reset_piv(ykman, CIP19_ADDRESS), SERIAL)

    def test_test_helper_encodes_what_the_guard_decodes(self):
        self.assertEqual(itest.wallet_key_hashes(TEST_ADDRESS),
                         (itest.key_hash(PAYMENT_PK), itest.key_hash(STAKE_PK)))


if __name__ == "__main__":
    unittest.main()
