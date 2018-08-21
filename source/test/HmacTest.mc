// Obtained the correct values from:
// http://www.freeformatter.com/hmac-generator.html
module HmacTest {

	(:test)
	function testDigestBasic1(logger) {
		var hash = new Crypto.Sha1Hash();
		var hmac = new Crypto.Hmac("abc".toUtf8Array(), "test".toUtf8Array(), hash);
		var digestBytes = hmac.fullyDigest();
		var digestHex = Crypto.bytesToHex(digestBytes);
		logger.debug(digestHex);
		BetterTest.assertEqual(digestHex, "3c38c442c961e29ca778a4e5927c596b750d3e67", "");
		return true;
	}

	(:test)
	function testDigestBasic2(logger) {
		var hash = new Crypto.Sha1Hash();
		var hmac = new Crypto.Hmac(";aslkdgfja;skdj803".toUtf8Array(), "tasdf asl;dkfj0392gsdfl;kghj".toUtf8Array(), hash);
		var digestBytes = hmac.fullyDigest();
		var digestHex = Crypto.bytesToHex(digestBytes);
		logger.debug(digestHex);
		BetterTest.assertEqual(digestHex, "db867bac14f8fd8c5e4dcdfff581ce099294bbe9", "");
		return true;
	}
}
