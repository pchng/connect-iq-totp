module CryptoTest {

	(:test)
	function testLeftRotate(logger) {
		logger.debug(0xffffffff + 1);
		BetterTest.assertEqual(Crypto.leftRotate(0xffffffff, 1), 0xffffffff, "0xffffffff rotated should be the same");
		BetterTest.assertEqual(Crypto.leftRotate(0x80000000, 1), 0x00000001, "0x80000000 rotated should be 1");
		BetterTest.assertEqual(Crypto.leftRotate(0x80808080, 1), 0x01010101, "");
		BetterTest.assertEqual(Crypto.leftRotate(0x10101010, 1), 0x20202020, "");
		return true;
	}

	(:test)
	function testUnsignedRightShiftLong(logger) {
		BetterTest.assertEqual(Crypto.unsignedRightShiftLong(-1L, 63), 1L, "");
		BetterTest.assertEqual(Crypto.unsignedRightShiftLong(-1L, 62), 3L, "");
		BetterTest.assertEqual(Crypto.unsignedRightShiftLong(-1L, 61), 7L, "");
		BetterTest.assertEqual(Crypto.unsignedRightShiftLong(-1L, 60), 15L, "");
		BetterTest.assertEqual(Crypto.unsignedRightShiftLong(15L, 2), 3L, "");
		return true;
	}

	(:test)
	function testLongToBytes(logger) {
		var bytes = Crypto.longToBytes(0xabcd1234l);
		BetterTest.assertEqual(Crypto.bytesToHex(bytes), "00000000abcd1234", "");

		bytes = Crypto.longToBytes(0xffffabcdl);
		BetterTest.assertEqual(Crypto.bytesToHex(bytes), "00000000ffffabcd", "");
		return true;
	}
}
