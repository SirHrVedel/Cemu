#include "wxgui/helpers/EmulatedKeyboardInput.h"

#include <wx/event.h>

#include "Cafe/OS/libs/nsyshid/EmulatedKeyboard.h"

// Translate a wxWidgets key code to a USB HID Keyboard/Keypad page (0x07) usage id.
// Returns 0 for keys we don't map or for pure modifier keys (the modifier bitmask carries those).
static uint8 wxKeyCodeToHidUsage(sint32 keyCode)
{
	if (keyCode >= 'A' && keyCode <= 'Z')
		return (uint8)(0x04 + (keyCode - 'A'));
	if (keyCode >= 'a' && keyCode <= 'z')
		return (uint8)(0x04 + (keyCode - 'a'));
	if (keyCode >= '1' && keyCode <= '9')
		return (uint8)(0x1E + (keyCode - '1'));
	if (keyCode >= WXK_F1 && keyCode <= WXK_F12)
		return (uint8)(0x3A + (keyCode - WXK_F1));
	switch (keyCode)
	{
	case '0': return 0x27;
	case WXK_RETURN:
	case WXK_NUMPAD_ENTER: return 0x28;
	case WXK_ESCAPE: return 0x29;
	case WXK_BACK: return 0x2A;
	case WXK_TAB: return 0x2B;
	case WXK_SPACE: return 0x2C;
	case '-': return 0x2D;
	case '=': return 0x2E;
	case '[': return 0x2F;
	case ']': return 0x30;
	case '\\': return 0x31;
	case ';': return 0x33;
	case '\'': return 0x34;
	case '`': return 0x35;
	case ',': return 0x36;
	case '.': return 0x37;
	case '/': return 0x38;
	case WXK_CAPITAL: return 0x39;
	case WXK_INSERT: return 0x49;
	case WXK_HOME: return 0x4A;
	case WXK_PAGEUP: return 0x4B;
	case WXK_DELETE: return 0x4C;
	case WXK_END: return 0x4D;
	case WXK_PAGEDOWN: return 0x4E;
	case WXK_RIGHT: return 0x4F;
	case WXK_LEFT: return 0x50;
	case WXK_DOWN: return 0x51;
	case WXK_UP: return 0x52;
	default: return 0;
	}
}

void FeedEmulatedKeyboard(const wxKeyEvent& event, bool pressed)
{
	uint8 modifiers = 0;
	if (event.ShiftDown())   modifiers |= 0x02; // Left Shift
	if (event.ControlDown()) modifiers |= 0x01; // Left Ctrl
	if (event.AltDown())     modifiers |= 0x04; // Left Alt
	if (event.MetaDown())    modifiers |= 0x08; // Left GUI
	const uint8 usage = wxKeyCodeToHidUsage(event.GetKeyCode());
	nsyshid::EmulatedKeyboardHandleKey(usage, modifiers, pressed);
}
