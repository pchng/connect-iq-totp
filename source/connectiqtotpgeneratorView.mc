using Toybox.WatchUi as Ui;
using Toybox.System as Sys;
using Toybox.Timer as Timer;
using Toybox.Time as Time;
using Toybox.Graphics as Graphics;

class connectiqtotpgeneratorView extends Ui.View {

    function initialize() {
        View.initialize();
    }

    // Load your resources here
    function onLayout(dc) {
    }

    // Called when this View is brought to the foreground. Restore
    // the state of this View and prepare it to be shown. This includes
    // loading resources into memory.
    hidden var _timer;
    function onShow() {
    	// TODO: Is this the best place to start the timer?
    	_timer = new Timer.Timer();
    	_timer.start(method (:computeTotp), 1000, true);
    }

	// HARD-CODED TEST KEY/SHARED SECRET:
	// NOTE: Doesn't have to be 10 bytes, but this one is.
	hidden var _key = [0x22, 0x04, 0xeb, 0xf6, 0xcf, 0xb4, 0x99, 0xa1, 0xec, 0x42];
	hidden var _totpGenerator = new Crypto.Totp(_key);
	hidden var _totp;
	hidden var _timeLeft;

    function computeTotp() {
    	var time = Time.now().value();
		_totp = _totpGenerator.generate(time);
		_timeLeft = _totpGenerator.timeLeft(time);
		Sys.println(_totp);

    	Ui.requestUpdate();
    }

    // Update the view
    function onUpdate(dc) {
        if (_totp) {
        	Sys.println("Drawing...");

			// Always keep the numbers white for readability.
        	dc.setColor(Graphics.COLOR_WHITE, Graphics.COLOR_BLACK);

        	dc.clear();

        	// TODO: Calculate ALL dimension (X, Y, radius, etc.) based on the screen dimensions of
        	// the device, don't hard-code like this!
        	var deviceWidth = dc.getWidth();
        	var deviceHeight = dc.getHeight();

        	var mainFont = Graphics.FONT_NUMBER_HOT;
        	var fontHeight = Graphics.getFontHeight(mainFont);
        	var x = deviceWidth / 2;
        	var y = (deviceHeight / 2) - (fontHeight / 2);

        	dc.drawText(x, y, mainFont, _totp, Graphics.TEXT_JUSTIFY_CENTER);

			var counterFont = Graphics.FONT_XTINY;
        	fontHeight = Graphics.getFontHeight(counterFont);
        	dc.drawText(x, deviceHeight - 1.5 * fontHeight, counterFont, _timeLeft, Graphics.TEXT_JUSTIFY_CENTER);

			// Countdown timer arc.
        	var foreground = Graphics.COLOR_WHITE;
        	if (_timeLeft < 10) {
        		foreground = Graphics.COLOR_RED;
        	}
        	dc.setColor(foreground, Graphics.COLOR_BLACK);
        	var fractionElapsed = (0.0 + 30 - _timeLeft)/ 30; // Coerce type to 32-bit floating-point.
        	var degreeStart = 90 - fractionElapsed*360;
        	dc.setPenWidth(5);
        	dc.drawArc(120, 120, 115, Graphics.ARC_CLOCKWISE, degreeStart, 90);
        }
    }

    // Called when this View is removed from the screen. Save the
    // state of this View here. This includes freeing resources from
    // memory.
    function onHide() {
    }

}


