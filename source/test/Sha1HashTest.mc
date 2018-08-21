module Sha1HashTest {

	(:test)
	function testDigestEmpty(logger) {
		var expectedBytes = [0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09];

		var hash = new Crypto.Sha1Hash();
		var digestBytes = hash.digest();

		BetterTest.assertEqual(digestBytes, expectedBytes, "");

		// Re-computing digest should yield the same result.
		BetterTest.assertEqual(hash.digest(), expectedBytes, "");

		return true;
	}

 	(:test)
	function testDigestBasic(logger) {
		var message = "The quick brown fox jumps over the lazy dog";
		var expectedBytes = [0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12];

		var hash = new Crypto.Sha1Hash();
		hash.update(message.toUtf8Array());
		var digestBytes = hash.digest();

		BetterTest.assertEqual(digestBytes, expectedBytes, "Digest of " + message + " equals: " + expectedBytes);

		return true;
	}

	(:test)
	function testDigestRepeated(logger) {
		var hash = new Crypto.Sha1Hash();

		var message = "The quick brown fox jumps over the lazy dog";
		var expectedBytes1 = [0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12];
		hash.update(message.toUtf8Array());
		BetterTest.assertEqual(hash.digest(), expectedBytes1, "");

		var message2 = "TEST";
		var expectedBytes2 = [0x4a, 0x4c, 0xe1, 0x82, 0xd9, 0x21, 0x86, 0x14, 0x0e, 0x4e, 0x9e, 0x96, 0x50, 0x2a, 0x85, 0x4c, 0xba, 0xe1, 0xca, 0x4b];
		hash.update(message2.toUtf8Array());
		BetterTest.assertEqual(hash.digest(), expectedBytes2, "");

		return true;
	}

	(:test)
	function testHexDigestEmpty(logger) {
		var hash = new Crypto.Sha1Hash();
		BetterTest.assertEqual(hash.hexDigest(), "da39a3ee5e6b4b0d3255bfef95601890afd80709", "");
		return true;
	}

	(:test)
	function testHexDigestBasic(logger) {
		var hash = new Crypto.Sha1Hash();
		hash.update("The quick brown fox jumps over the lazy dog".toUtf8Array());
		BetterTest.assertEqual(hash.hexDigest(), "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", "");
		return true;
	}

	(:test)
	function testHexDigestRepeated(logger) {
		var hash = new Crypto.Sha1Hash();
		hash.update("The quick brown fox jumps over the lazy dog".toUtf8Array());
		BetterTest.assertEqual(hash.hexDigest(), "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", "");
		hash.update("TEST".toUtf8Array());
		BetterTest.assertEqual(hash.hexDigest(), "4a4ce182d92186140e4e9e96502a854cbae1ca4b", "");
		return true;
	}

	(:test)
	function testHexDigestThenReset(logger) {
		var hash = new Crypto.Sha1Hash();
		hash.update("The quick brown fox jumps over the lazy dog".toUtf8Array());
		BetterTest.assertEqual(hash.hexDigest(), "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", "");
		// After reset, hash state should be that of an empty string.
		hash.reset();
		BetterTest.assertEqual(hash.hexDigest(), "da39a3ee5e6b4b0d3255bfef95601890afd80709", "");
		return true;
	}
}
