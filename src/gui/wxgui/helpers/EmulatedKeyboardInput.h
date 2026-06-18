#pragma once

class wxKeyEvent;

// Translate a host wx key event and forward it to the emulated USB keyboard (if one is attached).
// Shared by every window that can have keyboard focus (main window and gamepad view) so physical
// typing works regardless of which window is focused. No-op when the emulated keyboard is disabled.
void FeedEmulatedKeyboard(const wxKeyEvent& event, bool pressed);
