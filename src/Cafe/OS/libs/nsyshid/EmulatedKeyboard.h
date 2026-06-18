#pragma once

#include <array>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <vector>

#include "nsyshid.h"
#include "Backend.h"

namespace nsyshid
{
	// Arbitrary but stable IDs for the emulated keyboard. The native keyboard stack identifies
	// keyboards by HID interface class/protocol, not vendor/product. 0x1209 is the pid.codes
	// community vendor id; 0xCEEB is a Cemu-specific marker.
	constexpr uint16 EMULATED_KEYBOARD_VENDOR_ID = 0x1209;
	constexpr uint16 EMULATED_KEYBOARD_PRODUCT_ID = 0xCEEB;

	// Emulated USB HID boot keyboard. Presented to the guest as a single generic keyboard so that
	// the native nsyskbd.rpl/swkbd.rpl stack (which polls input reports through HIDRead) accepts
	// host keyboard input. Reports are standard 8-byte boot-protocol reports:
	//   [0] modifier bitmask, [1] reserved, [2..7] up to six pressed key usage codes.
	class EmulatedKeyboardDevice final : public Device
	{
	  public:
		EmulatedKeyboardDevice();
		~EmulatedKeyboardDevice() override;

		bool Open() override;
		void Close() override;
		bool IsOpened() override;

		ReadResult Read(ReadMessage* message) override;
		WriteResult Write(WriteMessage* message) override;

		bool GetDescriptor(uint8 descType,
						   uint8 descIndex,
						   uint16 lang,
						   uint8* output,
						   uint32 outputMaxLength) override;

		bool SetIdle(uint8 ifIndex, uint8 reportId, uint8 duration) override;
		bool SetProtocol(uint8 ifIndex, uint8 protocol) override;
		bool SetReport(ReportMessage* message) override;

		// Update key state from a host key event and queue a fresh boot report for the next
		// HIDRead. usageCode is a USB HID Keyboard/Keypad page (0x07) usage id, or 0 for a
		// modifier-only change. modifierMask is the current modifier bitmask (bit0 LCtrl,
		// bit1 LShift, bit2 LAlt, bit3 LGUI, ...).
		void HandleKey(uint8 usageCode, uint8 modifierMask, bool pressed);

		// Release all keys/modifiers (e.g. on focus loss) and report the empty state.
		void ReleaseAll();

	  private:
		// Builds an 8-byte boot report from the current state and queues it. Caller must hold m_reportMutex.
		void QueueReportFromStateLocked();

		bool m_isOpened = false;

		std::mutex m_reportMutex;
		std::condition_variable m_reportCV;
		std::queue<std::array<uint8, 8>> m_reportQueue;

		// current key state (guarded by m_reportMutex)
		uint8 m_modifiers = 0;
		std::vector<uint8> m_pressedKeys; // non-modifier usage codes, in press order
	};

	// Creates the emulated keyboard and registers it as the active instance returned by
	// GetEmulatedKeyboard(). Use this instead of constructing the device directly.
	std::shared_ptr<EmulatedKeyboardDevice> CreateEmulatedKeyboard();

	// Returns the currently attached emulated keyboard, or nullptr if none is attached.
	// Used by the host input layer to inject key reports.
	std::shared_ptr<EmulatedKeyboardDevice> GetEmulatedKeyboard();

	// Convenience wrappers for the host input layer; no-op if no emulated keyboard is attached.
	void EmulatedKeyboardHandleKey(uint8 usageCode, uint8 modifierMask, bool pressed);
	void EmulatedKeyboardReleaseAll();
} // namespace nsyshid
