#include "EmulatedKeyboard.h"

#include <algorithm>
#include <chrono>

namespace nsyshid
{
	// Standard USB HID boot keyboard report descriptor (63 bytes).
	static const uint8 s_keyboardReportDescriptor[] = {
		0x05, 0x01, // Usage Page (Generic Desktop)
		0x09, 0x06, // Usage (Keyboard)
		0xA1, 0x01, // Collection (Application)
		0x05, 0x07, //   Usage Page (Key Codes)
		0x19, 0xE0, //   Usage Minimum (224)
		0x29, 0xE7, //   Usage Maximum (231)
		0x15, 0x00, //   Logical Minimum (0)
		0x25, 0x01, //   Logical Maximum (1)
		0x75, 0x01, //   Report Size (1)
		0x95, 0x08, //   Report Count (8)
		0x81, 0x02, //   Input (Data, Variable, Absolute) ; modifier byte
		0x95, 0x01, //   Report Count (1)
		0x75, 0x08, //   Report Size (8)
		0x81, 0x01, //   Input (Constant) ; reserved byte
		0x95, 0x05, //   Report Count (5)
		0x75, 0x01, //   Report Size (1)
		0x05, 0x08, //   Usage Page (LEDs)
		0x19, 0x01, //   Usage Minimum (1)
		0x29, 0x05, //   Usage Maximum (5)
		0x91, 0x02, //   Output (Data, Variable, Absolute) ; LED report
		0x95, 0x01, //   Report Count (1)
		0x75, 0x03, //   Report Size (3)
		0x91, 0x01, //   Output (Constant) ; LED padding
		0x95, 0x06, //   Report Count (6)
		0x75, 0x08, //   Report Size (8)
		0x15, 0x00, //   Logical Minimum (0)
		0x25, 0x65, //   Logical Maximum (101)
		0x05, 0x07, //   Usage Page (Key Codes)
		0x19, 0x00, //   Usage Minimum (0)
		0x29, 0x65, //   Usage Maximum (101)
		0x81, 0x00, //   Input (Data, Array) ; key array (6 bytes)
		0xC0		// End Collection
	};
	static_assert(sizeof(s_keyboardReportDescriptor) == 0x3F);

	static std::mutex s_instanceMutex;
	static std::weak_ptr<EmulatedKeyboardDevice> s_instance;

	EmulatedKeyboardDevice::EmulatedKeyboardDevice()
		: Device(EMULATED_KEYBOARD_VENDOR_ID, EMULATED_KEYBOARD_PRODUCT_ID,
				 0,	   // interface index
				 1,	   // interface subclass: boot
				 1)	   // protocol: keyboard
	{
	}

	EmulatedKeyboardDevice::~EmulatedKeyboardDevice()
	{
		Close();
	}

	bool EmulatedKeyboardDevice::Open()
	{
		m_isOpened = true;
		return true;
	}

	void EmulatedKeyboardDevice::Close()
	{
		{
			std::lock_guard<std::mutex> lock(m_reportMutex);
			m_isOpened = false;
		}
		// wake any HIDRead blocked in Read()
		m_reportCV.notify_all();
	}

	bool EmulatedKeyboardDevice::IsOpened()
	{
		return m_isOpened;
	}

	Device::ReadResult EmulatedKeyboardDevice::Read(ReadMessage* message)
	{
		std::array<uint8, 8> report;
		{
			std::unique_lock<std::mutex> lock(m_reportMutex);
			// Block until a report is queued or the device is closed. A real interrupt-IN endpoint
			// simply waits for the next report rather than timing out, and the guest's keyboard
			// reader thread is dedicated to this, so blocking here is correct.
			m_reportCV.wait(lock, [this] {
				return !m_reportQueue.empty() || !m_isOpened;
			});
			if (!m_isOpened)
				return Device::ReadResult::Error;
			report = m_reportQueue.front();
			m_reportQueue.pop();
		}

		const uint32 copyLength = std::min<uint32>(message->length, (uint32)report.size());
		memcpy(message->data, report.data(), copyLength);
		message->bytesRead = copyLength;
		cemuLog_log(LogType::Force,
					"nsyshid emulated keyboard: delivered {}-byte report (mod=0x{:02x} key0=0x{:02x})",
					copyLength, report[0], report[2]);
		return Device::ReadResult::Success;
	}

	Device::WriteResult EmulatedKeyboardDevice::Write(WriteMessage* message)
	{
		// Keyboards have no host->device bulk/interrupt OUT data we need to act on.
		message->bytesWritten = message->length;
		return Device::WriteResult::Success;
	}

	bool EmulatedKeyboardDevice::GetDescriptor(uint8 descType,
											   uint8 descIndex,
											   uint16 lang,
											   uint8* output,
											   uint32 outputMaxLength)
	{
		// HID report descriptor request
		if (descType == 0x22)
		{
			memcpy(output, s_keyboardReportDescriptor,
				   std::min<uint32>(outputMaxLength, sizeof(s_keyboardReportDescriptor)));
			return true;
		}

		// Configuration descriptor (config + interface + HID + one interrupt-IN endpoint)
		uint8 configurationDescriptor[0x22];
		uint8* currentWritePtr = configurationDescriptor;
		// configuration descriptor
		*(uint8*)(currentWritePtr + 0) = 9;			// bLength
		*(uint8*)(currentWritePtr + 1) = 2;			// bDescriptorType (configuration)
		*(uint16be*)(currentWritePtr + 2) = 0x0022; // wTotalLength
		*(uint8*)(currentWritePtr + 4) = 1;			// bNumInterfaces
		*(uint8*)(currentWritePtr + 5) = 1;			// bConfigurationValue
		*(uint8*)(currentWritePtr + 6) = 0;			// iConfiguration
		*(uint8*)(currentWritePtr + 7) = 0x80;		// bmAttributes (bus powered)
		*(uint8*)(currentWritePtr + 8) = 0x32;		// MaxPower (100mA)
		currentWritePtr += 9;
		// interface descriptor
		*(uint8*)(currentWritePtr + 0) = 9;	   // bLength
		*(uint8*)(currentWritePtr + 1) = 0x04; // bDescriptorType (interface)
		*(uint8*)(currentWritePtr + 2) = 0;	   // bInterfaceNumber
		*(uint8*)(currentWritePtr + 3) = 0;	   // bAlternateSetting
		*(uint8*)(currentWritePtr + 4) = 1;	   // bNumEndpoints
		*(uint8*)(currentWritePtr + 5) = 3;	   // bInterfaceClass (HID)
		*(uint8*)(currentWritePtr + 6) = 1;	   // bInterfaceSubClass (boot)
		*(uint8*)(currentWritePtr + 7) = 1;	   // bInterfaceProtocol (keyboard)
		*(uint8*)(currentWritePtr + 8) = 0;	   // iInterface
		currentWritePtr += 9;
		// HID descriptor
		*(uint8*)(currentWritePtr + 0) = 9;									 // bLength
		*(uint8*)(currentWritePtr + 1) = 0x21;								 // bDescriptorType (HID)
		*(uint16be*)(currentWritePtr + 2) = 0x0111;							 // bcdHID 1.11
		*(uint8*)(currentWritePtr + 4) = 0x00;								 // bCountryCode
		*(uint8*)(currentWritePtr + 5) = 0x01;								 // bNumDescriptors
		*(uint8*)(currentWritePtr + 6) = 0x22;								 // bDescriptorType (report)
		*(uint16be*)(currentWritePtr + 7) = sizeof(s_keyboardReportDescriptor); // wDescriptorLength
		currentWritePtr += 9;
		// endpoint descriptor (interrupt IN)
		*(uint8*)(currentWritePtr + 0) = 7;			// bLength
		*(uint8*)(currentWritePtr + 1) = 0x05;		// bDescriptorType (endpoint)
		*(uint8*)(currentWritePtr + 2) = 0x81;		// bEndpointAddress (IN 1)
		*(uint8*)(currentWritePtr + 3) = 0x03;		// bmAttributes (interrupt)
		*(uint16be*)(currentWritePtr + 4) = 0x0008; // wMaxPacketSize (8 byte boot report)
		*(uint8*)(currentWritePtr + 6) = 0x0A;		// bInterval (10ms)
		currentWritePtr += 7;

		cemu_assert_debug((currentWritePtr - configurationDescriptor) == 0x22);

		memcpy(output, configurationDescriptor,
			   std::min<uint32>(outputMaxLength, sizeof(configurationDescriptor)));
		return true;
	}

	bool EmulatedKeyboardDevice::SetIdle(uint8 ifIndex, uint8 reportId, uint8 duration)
	{
		return true;
	}

	bool EmulatedKeyboardDevice::SetProtocol(uint8 ifIndex, uint8 protocol)
	{
		return true;
	}

	bool EmulatedKeyboardDevice::SetReport(ReportMessage* message)
	{
		// Output report = host LED state (caps/num/scroll lock). We have nothing to drive, so accept and ignore.
		return true;
	}

	void EmulatedKeyboardDevice::QueueReportFromStateLocked()
	{
		std::array<uint8, 8> report{};
		report[0] = m_modifiers;
		// report[1] is reserved
		if (m_pressedKeys.size() > 6)
		{
			// too many keys held at once -> rollover error (0x01 in all six key slots)
			for (size_t i = 2; i < 8; i++)
				report[i] = 0x01;
		}
		else
		{
			for (size_t i = 0; i < m_pressedKeys.size(); i++)
				report[2 + i] = m_pressedKeys[i];
		}
		m_reportQueue.push(report);
		m_reportCV.notify_one();
	}

	void EmulatedKeyboardDevice::HandleKey(uint8 usageCode, uint8 modifierMask, bool pressed)
	{
		cemuLog_log(LogType::Force, "nsyshid emulated keyboard: host key usage=0x{:02x} mod=0x{:02x} pressed={}",
					usageCode, modifierMask, pressed);
		std::lock_guard<std::mutex> lock(m_reportMutex);
		m_modifiers = modifierMask;
		if (usageCode != 0)
		{
			auto it = std::find(m_pressedKeys.begin(), m_pressedKeys.end(), usageCode);
			if (pressed)
			{
				if (it == m_pressedKeys.end())
					m_pressedKeys.push_back(usageCode);
			}
			else if (it != m_pressedKeys.end())
			{
				m_pressedKeys.erase(it);
			}
		}
		QueueReportFromStateLocked();
	}

	void EmulatedKeyboardDevice::ReleaseAll()
	{
		std::lock_guard<std::mutex> lock(m_reportMutex);
		if (m_modifiers == 0 && m_pressedKeys.empty())
			return;
		m_modifiers = 0;
		m_pressedKeys.clear();
		QueueReportFromStateLocked();
	}

	std::shared_ptr<EmulatedKeyboardDevice> CreateEmulatedKeyboard()
	{
		auto device = std::make_shared<EmulatedKeyboardDevice>();
		std::lock_guard<std::mutex> lock(s_instanceMutex);
		s_instance = device;
		return device;
	}

	std::shared_ptr<EmulatedKeyboardDevice> GetEmulatedKeyboard()
	{
		std::lock_guard<std::mutex> lock(s_instanceMutex);
		return s_instance.lock();
	}

	void EmulatedKeyboardHandleKey(uint8 usageCode, uint8 modifierMask, bool pressed)
	{
		if (auto keyboard = GetEmulatedKeyboard())
			keyboard->HandleKey(usageCode, modifierMask, pressed);
	}

	void EmulatedKeyboardReleaseAll()
	{
		if (auto keyboard = GetEmulatedKeyboard())
			keyboard->ReleaseAll();
	}
} // namespace nsyshid
