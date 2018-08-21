// TAKEN FROM: https://github.com/matco/badminton and modified.
using Toybox.System as Sys;
using Toybox.Test as Test;
using Toybox.Lang as Lang;

module BetterTest {

	function fail(message) {
		Sys.println("assert fails " + message);
		throw new AssertException(message);
	}

	function assertTrue(condition, message) {
		return Test.assertMessage(condition, message);
	}

	function assertFalse(condition, message) {
		return Test.assertMessage(!condition, message);
	}

	function assertNull(condition, message) {
		return Test.assertEqualMessage(condition, null, message);
	}

	function assertNotNull(condition, message) {
		return Test.assertNotEqualMessage(condition, null, message);
	}

	function assertEqual(actual, expected, message) {
		if ((actual instanceof Lang.Array) && (expected instanceof Lang.Array)) {
			if (actual.size() != expected.size()) {
				throw new Test.AssertException("assert equal [" + message + "] fails: expected " + expected + " - actual " + actual );
			}
			for (var i = 0; i < actual.size(); i++) {
				// TODO: This doesn't give a good error message, it should show the difference in the arrays.
				assertEqual(actual[i], expected[i], message);
			}
		}
		else if(actual has :equals) {
			if(!actual.equals(expected)) {
				throw new Test.AssertException("assert equal [" + message + "] fails: expected " + expected + " - actual " + actual );
				fail(message);
			}
		}
		else {
			assertSame(actual, expected, message);
		}
	}

	function assertSame(actual, expected, message) {
		if(actual != expected) {
			throw new Test.AssertException("assert same [" + message + "] fails: expected " + expected + " - actual " + actual);
		}
	}

}