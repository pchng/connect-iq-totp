using Toybox.System as Sys;

// NOTE: Connect IQ 3.0.1, released on 2018-08-16, added support for Crypto primitives
// https://developer.garmin.com/index.php/blog/post/connect-iq-3.0.1-now-available
// You should use those built-in constructs/APIs instead of this home-rolled solution, which
// remains just as a proof-of-concept. The SDK-provided crypto APIs are likely more secure, and
// faster.

// ----- USAGE NOTES AND DISCLAIMER -----
// 1) I am not a cryptographer nor am I a security expert. Since the implementation of these
// crypto primitives is outside of my domain of expertise, USE AT YOUR OWN RISK. These implementations
// may contain errors, weaknesses or other bugs that make them susceptible to attacks. I have made
// my best effort to implement them correctly, given the limitations of the Connect IQ SDK and
// the runtime environment, but I DO NOT RECOMMEND they be used in production or critical applications.
//
// 2) As you may know, SHA-1 is considered "broken", as collisions have been found, and practical
// attack methods are known. [1] One may reasonable ask then, "Why did you choose to implement
// SHA-1 instead of a SHA-2 algorithm, or something else that is not yet known to be broken?"
// The answer is this: My aim was to re-implement the functionality offered by the Google Authenticator
// mobile app [2][3] as a proof-of-concept for a Connect IQ program.
// This app uses the TOTP algorithm to generate one-time passwords that change every 30 seconds,
// and this algorithm is described by RFC 6238. [4] While this RFC permits for the use of
// SHA-256/512 instead of SHA-1, in practice, currently Google Authenticator ONLY supports SHA-1. [5]
//
// A full discussion of whether SHA-1 is "broken" in the context of HMAC is beyond my comprehension,
// but there is a good discussion by the authors of RFC 4226, which describes the HOTP algorithm,
// which is what TOTP is based on. In HOTP, only SHA-1 can be used, and there is discussion about
// the weaknesses already known about SHA-1 back in December 2005 when the RFC was written, and
// in particular what the ramifications on HMAC-SHA-1 would be if SHA-1 collisions were found: [6]
//
//    HMAC is not a hash function.  It is a message authentication code
//    (MAC) that uses a hash function internally.  A MAC depends on a
//    secret key, while hash functions don't.  What one needs to worry
//    about with a MAC is forgery, not collisions.  HMAC was designed so
//    that collisions in the hash function (here SHA-1) do not yield
//    forgeries for HMAC.
//    ...
//    Historically, the HMAC design has already proven itself in this
//    regard.  MD5 is considered broken in that collisions in this hash
//    function can be found relatively easily.  But there is still no
//    attack on HMAC-MD5 better than the trivial 2^{64} time birthday one.
//    (MD5 outputs 128 bits, not 160.)  We are seeing this strength of HMAC
//    coming into play again in the SHA-1 context.
//
// I will leave the reader to determine the suitability of the choice of HMAC-SHA1 in light of the
// above statements.
//
// 3) The Monkey C language does not (yet?) have a "byte" type. The closest thing is a 32-bit
// signed integer. Thus, all references to "byte" ("array of bytes", etc.) really mean a 32-bit
// integer that has been masked with 0xff to ensure only the lowest 8-bits can be set.
//
// 4) As a last note, USE THESE CRYPTO PRIMITIVE IMPLEMENTATIONS AT YOUR OWN RISK. They HAVE NOT
// BEEN AUDITED IN ANY MANNER. I have implemented these to the best of my ability, but they were
// only for my own proof-of-concept application.
//
// References:
// 1. https://shattered.io/
// 2. https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2
// 3. https://itunes.apple.com/us/app/google-authenticator/id388497605
// 4. https://tools.ietf.org/html/rfc6238
// 5. https://github.com/google/google-authenticator/wiki/Key-Uri-Format
// 6. https://tools.ietf.org/html/rfc4226#page-25
//
module Crypto {

	// ----- Utility Functions -----
	// TODO: Find out if we even need to mask by this, if calling .toNumber();
	hidden const BIT_MASK_32 = 0xffffffff;

	// Extracts the lowest byte from an integer value. Needed because there isn't a byte type in Monkey C.
	// @param n the value to extract the lowest byte from.
	// @return the lowest byte.
	function getByte(n) {
		return n & 0xff;
	}

	// Left rotate a 32-bit integer n by b bits.
	// @param n a 32-bit integer.
	// @param b the number of bits to rotate left by.
	// @return a 32-bit integer representing the left-rotated value.
	function leftRotate(n, b) {
		// return ((n << b) | (n >> (32 - b))) & 0xffffffff;
		if (b == 0) {
			return n;
		}
		// NOTE: Hack to workaround lack of unsigned right shift/unsigned types in Monkey C.
		// Find out if there's a better way.
		var rightShiftedPart = (n >> 1) & 0x7fffffff;
		rightShiftedPart =  (rightShiftedPart >> (31 - b));
		return (((n << b) | rightShiftedPart) & BIT_MASK_32).toNumber();
	}

	// Right unsigned shift for a long.
	// @param n 64-bit long integer.
	// @param b number of bits to right unsigned shift by.
	// @return a 64-bit long integer representing the shifted value.
	function unsignedRightShiftLong(n, b) {
		if (b <= 0) {
			return n;
		}

		var rightShift = n >> 1 & 0x7fffffffffffffffl;
		return rightShift >> (b - 1);
	}

	// @param bytes an array of bytes.
	// @return a hex string representing the bytes. Order is considered to be big endian.
	function bytesToHex(bytes) {
		var output = "";
		for (var i = 0; i < bytes.size(); i++) {
			output += (bytes[i] & 0xff).format("%02x");
		}
		return output;
	}

	// @param i a 64-bit integer
	// @return an array of big endian bytes representing it.
	function longToBytes(n) {
		if (!(n instanceof Toybox.Lang.Long)) {
			throw new Toybox.Lang.Exception("Must be a 64-bit long integer.");
		}
		var result = new[8];
		for (var i = 0; i < 8; i++) {
			// Note operator associativity matters!
			result[i] = ((n >> ((7-i)*8)) & 0xff).toNumber();
		}
		/*
		result[0] = ((n >> 56) & 0xff).toNumber();
		result[1] = ((n >> 48) & 0xff).toNumber();
		result[2] = ((n >> 40) & 0xff).toNumber();
		result[3] = ((n >> 32) & 0xff).toNumber();
		result[4] = ((n >> 24) & 0xff).toNumber();
		result[5] = ((n >> 16) & 0xff).toNumber();
		result[6] = ((n >> 8) & 0xff).toNumber();
		result[7] = (n & 0xff).toNumber();
		*/
		return result;
	}

	// Implementation of SHA-1 based off of:
	// - https://github.com/ajalt/python-sha1/blob/master/sha1.py
	// - https://en.wikipedia.org/wiki/SHA-1
	class Sha1Hash {
		// NOTE: MonkeyC does not have a "byte" type, so instead we're using arrays of 32-bit integers
		// instead. This is obviously inefficient, and as an improvement, we could use a single
		// 32-bit integer as 4 bytes. This obviously would complicate things when the number of bytes
		// is not an even multiple of 4.
		// Also note that "arrays" in Monkey C are really dynamic arrays, akin to Java's ArrayList or
		// Python's list types.
		hidden const CHUNK_SIZE_BYTES = 64;
		hidden const INITIAL_STATE = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

		// Initial digest variables, h0-h4. Note that Monkey C doesn't have unsigned integers, but
		// this mostly doesn't matter since the two's complement arithmetic works in the same manner
		// and bitwise operations are also unaffected.
		hidden var _h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

		// Unprocessed bytes with length of 0 <= len < 64 bytes used to store the end of the message
		// if the message length was congruent to 64 bytes, i.e. a multiple of 64 bytes.
		hidden var _unprocessed = new[0];
		hidden var _messageByteLength = 0l;

		// Process a 64-byte chunk and update the hash variables/state.
		// @param chunk consisting of 64 bytes. Because there is no "byte" type in Monkey C,
		// this should be an array of 64 32-bit integers.
		hidden function _processChunk(chunk, h) {
			// Length of chunk should be 64-bytes.
			// Should update h0-h4 values.
			if (chunk.size() != CHUNK_SIZE_BYTES) {
				throw new Toybox.Lang.Exception("Incorrect chunk size, should be: " + CHUNK_SIZE_BYTES);
			}

			// Used for storing 80 4-byte words.
			var w = new[80];

			// Break chunk into 16 4-byte big-endian words.
			for (var i = 0; i < 16; i++) {
				// Initially set each array value to 0.
				//w[i] = 0;
				var n = 0;
				n = (getByte(chunk[i*4]) << 24) | (getByte(chunk[i*4+1]) << 16) |
					(getByte(chunk[i*4+2]) << 8) | (getByte(chunk[i*4+3]));
				w[i] = n;
			}

			// Extend the 16 4-byte words into 80 4-byte words.
			for (var i = 16; i < 80; i++) {
				// Initially set each array value to 0;
				//w[i] = 0;
				w[i] = leftRotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
			}

			// Initialize hash values for this chunk.
			var a = h[0];
			var b = h[1];
			var c = h[2];
			var d = h[3];
			var e = h[4];
			var f = 0, k = 0;

			for (var i = 0; i < 80; i++) {
				if ((0 <= i) && (i <= 19)) {
					f = d ^ (b & (c ^ d));
					k = 0x5A827999;
				} else if ((20 <= i) && (i <= 39)) {
					f = b ^ c ^ d;
					k = 0x6ED9EBA1;
				} else if ((40 <= i) && (i <= 59)) {
					f = (b & c) | (b & d) | (c & d);
					k = 0x8F1BBCDC;
				} else if ((60 <= i) && (i <= 79)) {
					f = b ^ c ^ d;
					k = 0xCA62C1D6;
				}

				// TODO: Reduce to the minimum set that needs temporary copies.
				// Create copies to avoid overwriting.
				var aTemp = a;
				var bTemp = b;
				var cTemp = c;
				var dTemp = d;
				var eTemp = e;

				a = ((leftRotate(aTemp, 5) + f + eTemp + k + w[i]) & BIT_MASK_32);
				b = aTemp;
				c = leftRotate(bTemp, 30);
				d = cTemp;
				e = dTemp;
			}

			// Add this chunk's hash to the result so far.
			var h0 = (h[0] + a) & BIT_MASK_32;
			var h1 = (h[1] + b) & BIT_MASK_32;
			var h2 = (h[2] + c) & BIT_MASK_32;
			var h3 = (h[3] + d) & BIT_MASK_32;
			var h4 = (h[4] + e) & BIT_MASK_32;
			return [h0, h1, h2, h3, h4];
		}

		// Extract a chunk of UP TO chunkSize from bytes, starting from start.
		// May return a chunk of size 0 if there are no remaining bytes.
		// @param bytes the array to extract from.
		// @param start the starting index.
		// @param chunkSize the number of bytes to extract.
		hidden function _extractChunk(bytes, start, chunkSize) {
			var size = chunkSize;
			var remainingSize = bytes.size() - start;
			if (remainingSize < size) {
				size = remainingSize;
			}
			if (size < 0) {
				size = 0;
			}
			var chunk = new[size];
			for (var i = 0; i < size; i++) {
				chunk[i] = bytes[start + i];
			}
			return chunk;
		}

		// Update the current digest.
		// @param bytes an array of bytes; note that even if these are 32-bit integers, only the lowest 8 bits will be used.
		function update(bytes) {
			// 1) Combine with the remaining unprocessed bytes that could not form a 64-byte chunk by prepending the previous bytes.
			if (_unprocessed.size() > 0) {
				// Prepend the unprocessed bytes.
				bytes = _unprocessed.addAll(bytes);
			}

			// 2) Read 64-byte chunks and pass to _processChunk(): This should update the h0-h4 values.
			var i = 0;
			var chunk = _extractChunk(bytes, i, CHUNK_SIZE_BYTES);
			while (chunk.size() == CHUNK_SIZE_BYTES) {
				_h = _processChunk(chunk, _h);
				// 3) Increment message byte length by 64 for every successfully processed chunk.
				_messageByteLength += CHUNK_SIZE_BYTES;

				i += CHUNK_SIZE_BYTES;
				chunk = _extractChunk(bytes, i, CHUNK_SIZE_BYTES);
			}

			// 4) Set unprocessed to any remaining bytes that could not form a complete 64-byte chunk.
			// Chunk will contain any remaining bytes that could not form a complete 64-byte chunk.
			_unprocessed = chunk;

			return self;
		}

		// Produce the final hash output for the input so far passed in via update().
		// This does not alter the internal state of the hash.
		// This allows you to obtain the digest/hash of some initial data, append some more via
		// update(), and then call this method to get the digest/hash of the updated data.
		// @return the final state of the hash for all the input taken so far, as an array of five
		// 32-bit integer values.
		hidden function _produceDigest() {
			// Don't modify _unprocessed so that the internal hash state is not modified; so create
			// a copy of _unprocessed.
			var message = _unprocessed.slice(0, _unprocessed.size());

			// Pre-processing.
			var messageByteLength = _messageByteLength + _unprocessed.size();

			// Produce the final chunk(s).
			// Because the end padding data is AT LEAST 9 more bytes (0x80 followed by 8-bytes/64-bits
			// for the message bit length), if the unprocessed bytes are > 55, then we'll have two chunks.
			var finalMessageSize = (_unprocessed.size() > CHUNK_SIZE_BYTES - 9) ? 2 * CHUNK_SIZE_BYTES : CHUNK_SIZE_BYTES;

			// Append the bit '1' to the message, aka 0x80.
			message.add(0x80);

			// Pad with enough zero bytes to make it a full chunk.
			while (message.size() < finalMessageSize) {
				message.add(0x00);
			}

			// Calculate the message length in bits.
			var messageLengthBits = 8l * messageByteLength;

			// Append the message length in bits, as a 64-bit big-endian integer, in the last 8 bytes
			// of the last chunk.
			var start = message.size() - 8;
			for (var i = 0; i < 8; ++i) {
				var bitShift = (7 - i) * 8; // 56, 48, 40, 32, ..., 0
				message[start + i] = unsignedRightShiftLong(messageLengthBits, bitShift).toNumber() & 0xff;
			}

			// Process the final chunk(s).
			// At this point the length of message is either 64 or 128 bytes. (1 or 2 chunks)
			var i = 0;
			var chunk = _extractChunk(message, i, CHUNK_SIZE_BYTES);
			var h = _h;
			while (chunk.size() == CHUNK_SIZE_BYTES) {
				// Produce the final hash output, but don't update the internal state so that
				// update() can be called after this to update the hash state with more input.
				// This allows the hash to be reused for input with a common prefix to prevent
				// recalcuation.
				h = _processChunk(chunk, h);
				i += CHUNK_SIZE_BYTES;
				chunk = _extractChunk(message, i, CHUNK_SIZE_BYTES);
			}

			// Return final hash state.
			return h;
		}

		// Produce the final digest as an array of bytes.
		// @return an array of bytes representing the hash digest. For SHA-1 it will be an array
		// of 20 bytes, since the hash length is 160 bits.
		function digest() {
			// This will be five 32-bit integers.
			var hash = _produceDigest();

			// Convert to 20 bytes.
			var result = new[20];
			for (var i = 0; i < hash.size(); i++) {
				// Each 32-bit integer is four BIG-ENDIAN bytes, so the MSB comes first.
				var w = hash[i];
				result[i*4] = (w >> 24) & 0xff;
				result[i*4 + 1] = (w >> 16) & 0xff;
				result[i*4 + 2] = (w >> 8) & 0xff;
				result[i*4 + 3] = w & 0xff;
			}
			return result;
		}

		// Produce the final digest as a hex-encoded string.
		// @return a string with the hex representation of the hash/digest. For SHA-1, it will
		// be 40 characters long, since the hash length is 160 bits. All characters will be lowercase.
		function hexDigest() {
			// This will be five 32-bit integers.
			var hash = _produceDigest();
			var output = "";
			for (var i = 0; i < hash.size(); i++) {
				// Ensure any leading zeros are preserved.
				output += hash[i].format("%08x");
			}
			return output;
		}

		// Resets the hash's state back to the initial values so the same instance can be reused
		// for hashing different content.
		function reset() {
			_h = INITIAL_STATE.slice(0, INITIAL_STATE.size());
			_unprocessed = new[0];
			_messageByteLength = 0l;
		}

		// @return the size of this hash's block in bytes.
		function getBlockSizeBytes() {
			return CHUNK_SIZE_BYTES;
		}
	}

	// HMAC implementation based on the pseudocode here:
	// https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
	class Hmac {

		hidden var _key;
		hidden var _message;
		hidden var _hash;
		hidden var _blockSizeBytes;

		// Keep track of which step we're at in the digest computation, so that it can broken up
		// into separate steps that do not trip the watchdog.
		hidden var _step = 0;

		// Shared state in between steps.
		hidden var _oKeyPad;
		hidden var _innerDigest;

		// Final digest calculation stored here.
		hidden var _digest;


		// NOTE: For now, just a basic API which DOES NOT support repeated update()/digest()
		// calls; a single instance corresponds to a SINGLE tuple of (key, message, hash)

		// @param the key as an array of bytes. Because Monkey C doesn't have a byte type, this
		// should be an array of 32-bit integers. Only the lowest 8-bits will be used, i.e. masked
		// with 0xff.
		// @param the message as an array of bytes. (aka 32-bit Monkey C integers for the same
		// reasons as above)
		// @param hashInstance an instance of a hash function. It should the update(), digest() and reset()
		// methods.
		function initialize(key, message, hash) {

			Sys.println("Creating HMAC.");

			if (!(key instanceof Toybox.Lang.Array) || !(message instanceof Toybox.Lang.Array)) {
				throw new Toybox.Lang.Exception("Both key and message must be an array.");
			}
			if (!(hash has :update) || !(hash has :digest) || !(hash has :reset) || !(hash has :getBlockSizeBytes)) {
				throw new Toybox.Lang.Exception("Hash function instance must have getBlockSizeBytes(), update(), digest() and reset() methods.");
			}
			_hash = hash;
			_blockSizeBytes = _hash.getBlockSizeBytes();

			// Just to make sure it's back in the initial state.
			_hash.reset();

			_key = key;
			_message = message;
		}

		// NOTE: This may cause the watchdog timer to trip!
		// @return an array of bytes (32-bit integers with only the lowest 8-bits set) representing
		// the output from the HMAC function.
		function fullyDigest() {
			var digest = digest();
			while (!(digest instanceof Toybox.Lang.Array)) {
				digest = digest();
			}
			return digest;
		}

		// Computes the HMAC of the key and message using the provided hash, which were all
		// provided in the constructor.
		// You may have to call this method MULTIPLE times in order to get a digest. This is because
		// the computations were broken down into separate steps so as not to trip the watchdog
		// timer by doing them all at once. If digest() returns false, then more invocations are
		// needed. You can schedule the calls using a Timer.
		// Once the digest has been computed, it will be returned, and cached so that subsequent
		// calls always return it immediately.
		// NOTE: This HMAC implementation does not allow for repeated update()/digest() cycles,
		// unlike the Sha1Hash class. This is why there is only a single digest() method.
		// @return an array of 32-bit integers representing the output from the HMAC function, or
		// 		   false if more steps remain, and digest() must be called again.
		function digest() {
			// Return digest value immediately if already computed.
			if (_digest) {
				Sys.println("DIGEST ALREADY COMPUTED");
				return _digest.slice(0, _digest.size());
			}

			if (_step == 0) {
				Sys.println("STEP 0");
				// Keys longer than the block size are shortened.
				if (_key.size() > _blockSizeBytes) {
					_hash.update(_key);
					_key = _hash.digest();
					_hash.reset();
				}

				// Pad the key with zero-bytes so its length is equal to the block size.
				// Note that this will also happen if the block size
				if (_key.size() < _blockSizeBytes) {
					var extraPadding = _blockSizeBytes - _key.size();
					for (var i = 0; i < extraPadding; i++) {
						_key.add(0);
					}
				}

				_step++;
				return false;
			} else if (_step == 1) {
				Sys.println("STEP 1");
				// Outer and inner padding to the key.
				_oKeyPad = new[_blockSizeBytes];
				var iKeyPad = new[_blockSizeBytes];
				for (var i = 0; i < _key.size(); i++) {
					_oKeyPad[i] = (0x5c ^ _key[i]) & 0xff;
					iKeyPad[i] = (0x36 ^ _key[i]) & 0xff;
				}
				// Don't need iKeyPad after this.
				var innerBytes = iKeyPad;
				innerBytes.addAll(_message);

				_hash.update(innerBytes);
				_innerDigest = _hash.digest();
				_hash.reset();

				_step++;
				return false;
			} else {
				Sys.println("STEP 2");
				// Don't need oKeyPad after this.
				var outerBytes = _oKeyPad;
				outerBytes.addAll(_innerDigest);

				_hash.update(outerBytes);
				_digest = _hash.digest();
				return _digest.slice(0, _digest.size());
			}
		}
	}

	// Implementation of the TOTP algorithm as described in RFC 6238:
	// https://tools.ietf.org/html/rfc6238#appendix-A
	// Note that while the RFC indicates other hash algorithms can be used, such as SHA-256/512,
	// this implementation uses SHA-1, since currently the Google Authenticator app only uses
	// SHA1 as the HMAC's hashing function:
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	class Totp {

		// TOTP changes every 30 seconds.
		// NOTE: T0 is 0 and thus has no effect; it can be removed.
		const TIME_STEP = 30L;
		const T0 = 0l;
		const NUM_DIGITS = 6;
		const MOD_FACTOR = Toybox.Math.pow(10, NUM_DIGITS).toNumber(); // Could just hard code this directly.

		hidden var _key;
		hidden var _step;
		hidden var _totp;

		hidden var _hash;
		hidden var _hmac;

		// @param key the key in bytes.
		// @param hmac the HMAC function instance to use. It should have the digest() method.
		function initialize(key) {
			_key = key;

			// TODO: Should be able to specify the hash used with HMAC; shouldn't be hard-coded like this.
			_hash = new Sha1Hash();
		}

		// @param time the unix timestamp in seconds.
		// @return the number of seconds until a new TOTP code is generated.
		function timeLeft(time) {
			return (TIME_STEP - (time % TIME_STEP)).toNumber();
		}

		// TODO: Write a STEP version of this that can be called repeatedly in TIME-SLICES
		// to produce the proper result if the watchdog timer becomes an issue.

		// @param time the unix timestamp in seconds.
		// @return the 6-digit TOTP according to RFC 5238.
		function generate(time) {
			var step = (time - T0)/TIME_STEP;
			if (_step == step) {
				// Same step as last time computed, return.
				Sys.println("Step was the same as before, returning existing TOTP value.");
				return _totp;
			}
			_step = step;

			Sys.println("Computing TOTP for time: " + time);

			// Step should be a 64-bit integer; convert it to an array of 8 big-endian bytes.
			// This will become the message for HMAC.
			var stepBytes = longToBytes(step);

			// NOTE: For now, just using fullyDigest();
			_hmac = new Hmac(_key, stepBytes, _hash);
			var digest = _hmac.fullyDigest();

			// Offset is the low-order 4 bits of the last byte of the digest.
			// Thus the max value is 15; corresponding to bytes 15-18 of the
			// digest; since the minimum byte length is 20 (corresponding to
			// HMAC-SHA1) this will never go out of bounds.
			var offset = digest[digest.size() - 1] & 0xf;

			// Extract four bytes from the hash/digest to produce a 32-bit value.
			var totp = ((digest[offset] & 0x7f) << 24) |
         		((digest[offset + 1] & 0xff) << 16) |
         		((digest[offset + 2] & 0xff) << 8) |
         		((digest[offset + 3] & 0xff));

			_totp = (totp % MOD_FACTOR).format("%06d");
			return _totp;
		}

	}
}
