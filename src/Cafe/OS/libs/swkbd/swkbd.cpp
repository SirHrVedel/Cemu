#include "Cafe/OS/common/OSCommon.h"
#include "Cafe/HW/Latte/ISA/RegDefines.h"
#include "Cafe/OS/libs/gx2/GX2.h"
#include "Cafe/HW/Latte/Core/Latte.h"
#include "Cafe/HW/Latte/Core/LatteDraw.h"

#include "Cafe/HW/Latte/Renderer/Renderer.h"

#include <imgui.h>
#include "imgui/imgui_extension.h"
#include "util/helpers/helpers.h"
#include "resource/IconsFontAwesome5.h"

#define SWKBD_FORM_STRING_MAX_LENGTH	(4096) // counted in 16-bit characters

#define SWKBD_STATE_BLANK				(0)	// not visible
#define SWKBD_STATE_APPEARING			(1)	// fade-in ?
#define SWKBD_STATE_DISPLAYED			(2)	// visible
#define SWKBD_STATE_DISAPPEARING		(3)	// fade-out ?

typedef struct  
{
	uint32 ukn00; // constructor?
	uint32 ukn04; // destructor?
	uint32 ukn08; // ?
	MEMPTR<void> changeString; // some function address
}SwkbdIEventReceiverVTable_t;

typedef struct  
{
	MEMPTR<SwkbdIEventReceiverVTable_t> vTable;
	// todo - more elements? (currently separated from this struct)
}SwkbdIEventReceiver_t;

struct swkbdReceiverArg_t
{
	MEMPTR<SwkbdIEventReceiver_t> IEventReceiver;
	MEMPTR<sint16be> stringBuf;
	sint32be stringBufSize;
	sint32be fixedCharLimit;
	sint32be cursorPos;
	sint32be selectFrom;
};

typedef struct  
{
	uint32 ukn000;
	uint32 controllerType;
	uint32 keyboardMode; // guessed
	uint32 ukn00C;
	uint32 ukn010;
	uint32 ukn014;
	uint32 ukn018;
	uint32 ukn01C; // ok string?
	uint32 ukn020[4];
	uint32 ukn030[4];
	uint32 ukn040[4];
	uint32 ukn050[4];
	uint32 ukn060[4];
	uint32 ukn070[4];
	uint32 ukn080[4];
	uint32 ukn090[4];
	uint32 ukn0A0;
	uint32 ukn0A4;
	//uint32 ukn0A8;
	//MEMPTR<SwkbdIEventReceiver_t> IEventReceiver;
	swkbdReceiverArg_t receiverArg;
}SwkbdKeyboardArg_t;

typedef struct  
{
	// this structure resides in PPC addressable memory space
	wchar_t formStringBuffer[SWKBD_FORM_STRING_MAX_LENGTH];
	sint32 formStringLength;
	// big endian version of the string buffer (converted whenever GetInputFormString is called)
	uint16 formStringBufferBE[SWKBD_FORM_STRING_MAX_LENGTH];
	bool isActive; // set when SwkbdAppearInputForm() is called
	//bool isDisplayed; // set when keyboard is rendering
	bool decideButtonWasPressed; // set to false when keyboard appears, and set to true when enter is pressed. Remains on true after the keyboard is disappeared (todo: Investigate how this really works)
	// keyboard only mode (no input form)
	bool keyboardOnlyMode;
	SwkbdKeyboardArg_t keyboardArg;
	// input form appear args
	sint32 maxTextLength;
	// decision flags (mirrors real swkbd: game polls these, then calls DisappearInputForm)
	bool cancelButtonWasPressed; // set when back button is pressed; checked by SwkbdIsDecideCancelButton
	// info label supplied by the game via AppearArg::infoText (shown above the text field)
	wchar_t infoTextBuffer[256];
	// keyboard layout mode (set from appearArg when keyboard appears)
	uint32 inputType;
	uint32 okButtonMode;      // 0=normal (≥minTextLength chars), 1=enterPress (same), 2=always disabled, 3=always enabled; ≥4 clamped→0
	uint32 fullWidthMode;     // 0=half-width (ASCII), 1=full-width (wide/Japanese)
	uint32 disableKeyGroup;   // bitmask of disabled key groups; bit 15 = alphabetic group
	uint32 inputFormType;     // 0=single-line input, 1=multi-line (large) input
	// specialKeyOption (AppearArg+0x28): each bit ADDS an optional character to the keyboard.
	// The base layout does not include these chars; the game must opt in per character.
	// Confirmed bit mapping from swkbd.rpl sub_02081680 disassembly:
	//   bit 2  (0x004) '@'   bit 3  (0x008) '%'   bit 4  (0x010) '/'
	//   bit 5  (0x020) '\'   bit 6  (0x040) digit row (0-9)   bit 10 (0x400) '_'
	uint32 specialKeyOption;
	sint32 minTextLength;     // okMode=0: OK disabled until this many chars entered (≥1 by default)
	// imgui keyboard drawing stuff
	bool shiftActivated;
	bool returnState;
	bool cancelState;
	// OK button explicit override (set by SwkbdSetEnableOkButton)
	bool okButtonHasOverride;  // true when SwkbdSetEnableOkButton has been called
	bool okButtonDisabledByOverride; // !arg passed to SetEnableOkButton
	// text input cursor (insertion point within formStringBuffer)
	sint32 cursorPos;
	// controller cursor position on the key grid
	sint32 navRow;
	sint32 navCol;
	uint8  navHeldDirs;   // bitmask of d-pad directions held last frame (prevents held-down repeat)
	bool   activateHeld;  // A button was held last frame
	bool   shoulderLHeld; // L shoulder was held last frame
	bool   shoulderRHeld; // R shoulder was held last frame
	bool   lstickHeld;    // left stick click was held last frame

}swkbdInternalState_t;

swkbdInternalState_t* swkbdInternalState = NULL;

// Per-element base font sizes in pixels at the 720p baseline.
// Each value is scaled automatically to the actual canvas height
// exactly like the global 52px baseline is today.
static float swkbd_fontSizeKeys  = 52.0f;  // key button labels
static float swkbd_fontSizeHint  = 36.0f;  // hint / info label above the input field
static float swkbd_fontSizeInput = 52.0f;  // text inside the input field

void swkbdExport_SwkbdCreate(PPCInterpreter_t* hCPU)
{
	cemuLog_logDebug(LogType::Force, "swkbd.SwkbdCreate(0x{:08x},0x{:08x},0x{:08x},0x{:08x})", hCPU->gpr[3], hCPU->gpr[4], hCPU->gpr[5], hCPU->gpr[6]);
	if( swkbdInternalState == NULL )
	{
		MPTR swkbdInternalStateMPTR = coreinit_allocFromSysArea(sizeof(swkbdInternalState_t), 4);
		swkbdInternalState = (swkbdInternalState_t*)memory_getPointerFromVirtualOffset(swkbdInternalStateMPTR);
		memset(swkbdInternalState, 0x00, sizeof(swkbdInternalState_t));
	}
	osLib_returnFromFunction(hCPU, 0); // should return true?
}

static uint32 swkbd_getState()
{
	return swkbdInternalState->isActive ? SWKBD_STATE_DISPLAYED : SWKBD_STATE_BLANK;
}

void swkbdExport_SwkbdGetStateKeyboard(PPCInterpreter_t* hCPU)
{
	osLib_returnFromFunction(hCPU, swkbd_getState());
}

void swkbdExport_SwkbdGetStateInputForm(PPCInterpreter_t* hCPU)
{
	osLib_returnFromFunction(hCPU, swkbd_getState());
}

//ReceiverArg:
//+0x00	IEventReceiver*
//+0x04	stringBuf
//+ 0x08	stringBufSize
//+ 0x0C	fixedCharNumLimit(-1)
//+ 0x10	cursorPos
//+ 0x14	selectFrom(-1)
//
//IEventReceiver:
//+0x00 IEventReceiver_vTable*
//+0x04 ?
//+0x08 ?
//+0x0C ?
//
//IEventReceiver_vTable :
//	+0x00 ?
//	+0x04 ?
//	+0x08 ?
//	+0x0C	functionPtr onDirtyString(const DirtyInfo& info) = 0; ->DirtyInfo is just two DWORDs.From and to ?
//	?


void swkbdExport_SwkbdSetReceiver(PPCInterpreter_t* hCPU)
{
	debug_printf("SwkbdSetReceiver(0x%08x)\n", hCPU->gpr[3]);
	swkbdReceiverArg_t* receiverArg = (swkbdReceiverArg_t*)memory_getPointerFromVirtualOffset(hCPU->gpr[3]);

	if(swkbdInternalState == nullptr)
	{
		osLib_returnFromFunction(hCPU, 0);
		return;
	}

	swkbdInternalState->keyboardArg.receiverArg = *receiverArg;

	osLib_returnFromFunction(hCPU, 0);
}

typedef struct
{
	// Confirmed
	/* +0x00 */ uint32be inputType;        // keyboard layout enum 0-12 (≥13 rejected)
	/* +0x04 */ uint32be passwordMode;     // 0-4; 4 = swap dim panel to DRC instead of TV
	/* +0x08 */ uint32be okButtonMode;     // 0=normal 1=enterPress 2=disabled 3=ukn; ≥4 clamped→0
	/* +0x0C */ uint32be disableKeyGroup;  // bitmask. Disables key groups; different masks applied per display mode

	
	/* +0x10 */ uint32be ukn10[4];

	// Partially identified
	/* +0x20 */ uint32be ukn20;
	/* +0x24 */ uint8    fullWidthMode;    // 0=half-width/numeric (numpad), 1=full-width (QWERTY); lbz confirmed
	/* +0x25 */ uint8    pad25[3];
	/* +0x28 */ uint32be specialKeyOption; // bitmask enabling special keys: @, %, /, \, digit-row, etc.

	/* +0x2C */ uint32be ukn2C[28];
	/* +0x9C */ uint32be languageType;     // 0/negative normalised→1 (auto) by firmware
	/* +0xA0 */ uint32be uknA0[8];

	/* +0xC0 */ uint32be  inputFormType;  // 0=keyboard-only (no input box), 1=with input form; ≥2 clamped→1
	/* +0xC4 */ uint32be  cursorIndex;    // initial cursor position; clamped to textLength
	/* +0xC8 */ MEMPTR<uint16be> initialText; // NULL = start empty
	/* +0xCC */ MEMPTR<uint16be> hintText;    // NULL = no hint text shown
	/* +0xD0 */ uint32be  maxTextLength;  // 0 = default (40 chars)
	/* +0xD4 */ uint32be  insertionModeMask; // stored→instance+0x278; per-char insertable positions bitmask
	/* +0xD8 */ uint32be  preselectMask;     // stored→instance+0x254; preselected chars / cursor reference
	/* +0xDC */ uint8     ukn_DC;            // inverted (xori 1) before storing→instance+0x25c ("disable X"→"enable X")
	/* +0xDD */ uint8     pad_DD[3];

}swkbdAppearArg_t;

static_assert(offsetof(swkbdAppearArg_t, cursorIndex) == 0xC4, "appearArg.cursorIndex has invalid offset");

static void swkbd_resetNavState()
{
	swkbdInternalState->infoTextBuffer[0] = L'\0';
	swkbdInternalState->navRow        = 0;
	swkbdInternalState->navCol        = 0;
	swkbdInternalState->cursorPos     = 0;
	swkbdInternalState->navHeldDirs   = 0;
	swkbdInternalState->activateHeld  = false;
	swkbdInternalState->shoulderLHeld = false;
	swkbdInternalState->shoulderRHeld = false;
	swkbdInternalState->lstickHeld    = false;
}

// Common session initialisation shared by AppearInputForm and AppearKeyboard.
// Resets the COMPLETE keyboard state to defaults so nothing leaks between sessions
// (the swkbdInternalState allocation persists for the lifetime of the process).
// The caller overwrites the layout/behaviour fields it cares about immediately after.
static void swkbd_beginSession(bool keyboardOnly)
{
	// ── Layout / behaviour config (sane defaults; Appear* overrides as needed) ──
	swkbdInternalState->inputType        = 0;
	swkbdInternalState->okButtonMode     = 0;
	swkbdInternalState->fullWidthMode    = 0;
	swkbdInternalState->disableKeyGroup  = 0;
	swkbdInternalState->inputFormType    = 0;
	swkbdInternalState->specialKeyOption = 0;
	swkbdInternalState->minTextLength    = 1;
	swkbdInternalState->maxTextLength    = SWKBD_FORM_STRING_MAX_LENGTH - 1;
	// ── OK-button override (SwkbdSetEnableOkButton) ──
	swkbdInternalState->okButtonHasOverride        = false;
	swkbdInternalState->okButtonDisabledByOverride = false;
	// ── Visibility / decision flags ──
	swkbdInternalState->isActive               = true;
	swkbdInternalState->keyboardOnlyMode       = keyboardOnly;
	swkbdInternalState->decideButtonWasPressed = false;
	swkbdInternalState->cancelButtonWasPressed = false;
	// ── Text buffer ──
	swkbdInternalState->formStringBuffer[0] = L'\0';
	swkbdInternalState->formStringLength    = 0;
	// ── UI / controller edge-detect state ──
	// These are not touched by the Appear* handlers and would otherwise persist
	// across sessions (e.g. shift staying latched on, or a held button carrying over).
	swkbdInternalState->shiftActivated = false;
	swkbdInternalState->returnState    = false;
	swkbdInternalState->cancelState    = false;
	swkbd_resetNavState();
}

void swkbdExport_SwkbdAppearInputForm(PPCInterpreter_t* hCPU)
{
	ppcDefineParamStructPtr(appearArg, swkbdAppearArg_t, 0);
	cemuLog_logDebug(LogType::Force, "SwkbdAppearInputForm__3RplFRCQ3_2nn5swkbd9AppearArg");
	cemuLog_log(LogType::Force,
	    "SWKBD AppearInputForm: inputType={} passwordMode={} okButtonMode={} "
	    "disableKeyGroup={:#010x} fullWidthMode={} specialKeyOption={:#010x} "
	    "languageType={} maxTextLength={} insertionModeMask={:#010x} "
	    "preselectMask={:#010x} inputFormType={} ukn_DC={}",
	    (uint32)appearArg->inputType, (uint32)appearArg->passwordMode,
	    (uint32)appearArg->okButtonMode, (uint32)appearArg->disableKeyGroup,
	    (uint32)appearArg->fullWidthMode, (uint32)appearArg->specialKeyOption,
	    (uint32)appearArg->languageType, (uint32)appearArg->maxTextLength,
	    (uint32)appearArg->insertionModeMask, (uint32)appearArg->preselectMask,
	    (uint32)appearArg->inputFormType, (uint32)appearArg->ukn_DC);
	// Dump unknown fields to identify minTextLength and other unresolved parameters.
	cemuLog_log(LogType::Force,
	    "SWKBD ukn10[]: {:08x} {:08x} {:08x} {:08x}  ukn20={:08x}",
	    (uint32)appearArg->ukn10[0], (uint32)appearArg->ukn10[1],
	    (uint32)appearArg->ukn10[2], (uint32)appearArg->ukn10[3],
	    (uint32)appearArg->ukn20);
	cemuLog_log(LogType::Force,
	    "SWKBD ukn2C[00-07]: {:08x} {:08x} {:08x} {:08x}  {:08x} {:08x} {:08x} {:08x}",
	    (uint32)appearArg->ukn2C[0],  (uint32)appearArg->ukn2C[1],
	    (uint32)appearArg->ukn2C[2],  (uint32)appearArg->ukn2C[3],
	    (uint32)appearArg->ukn2C[4],  (uint32)appearArg->ukn2C[5],
	    (uint32)appearArg->ukn2C[6],  (uint32)appearArg->ukn2C[7]);
	cemuLog_log(LogType::Force,
	    "SWKBD ukn2C[08-15]: {:08x} {:08x} {:08x} {:08x}  {:08x} {:08x} {:08x} {:08x}",
	    (uint32)appearArg->ukn2C[8],  (uint32)appearArg->ukn2C[9],
	    (uint32)appearArg->ukn2C[10], (uint32)appearArg->ukn2C[11],
	    (uint32)appearArg->ukn2C[12], (uint32)appearArg->ukn2C[13],
	    (uint32)appearArg->ukn2C[14], (uint32)appearArg->ukn2C[15]);
	cemuLog_log(LogType::Force,
	    "SWKBD ukn2C[16-27]: {:08x} {:08x} {:08x} {:08x}  {:08x} {:08x} {:08x} {:08x}  {:08x} {:08x} {:08x} {:08x}",
	    (uint32)appearArg->ukn2C[16], (uint32)appearArg->ukn2C[17],
	    (uint32)appearArg->ukn2C[18], (uint32)appearArg->ukn2C[19],
	    (uint32)appearArg->ukn2C[20], (uint32)appearArg->ukn2C[21],
	    (uint32)appearArg->ukn2C[22], (uint32)appearArg->ukn2C[23],
	    (uint32)appearArg->ukn2C[24], (uint32)appearArg->ukn2C[25],
	    (uint32)appearArg->ukn2C[26], (uint32)appearArg->ukn2C[27]);
	cemuLog_log(LogType::Force,
	    "SWKBD uknA0[]: {:08x} {:08x} {:08x} {:08x}  {:08x} {:08x} {:08x} {:08x}",
	    (uint32)appearArg->uknA0[0], (uint32)appearArg->uknA0[1],
	    (uint32)appearArg->uknA0[2], (uint32)appearArg->uknA0[3],
	    (uint32)appearArg->uknA0[4], (uint32)appearArg->uknA0[5],
	    (uint32)appearArg->uknA0[6], (uint32)appearArg->uknA0[7]);
	swkbd_beginSession(false);
	swkbdInternalState->inputType        = (uint32)appearArg->inputType;
	swkbdInternalState->okButtonMode     = (uint32)appearArg->okButtonMode;
	swkbdInternalState->fullWidthMode    = (uint32)appearArg->fullWidthMode;
	swkbdInternalState->disableKeyGroup  = (uint32)appearArg->disableKeyGroup;
	swkbdInternalState->inputFormType    = (uint32)appearArg->inputFormType;
	swkbdInternalState->specialKeyOption = (uint32)appearArg->specialKeyOption;

	// setup max text length
	swkbdInternalState->maxTextLength = (sint32)(uint32)appearArg->maxTextLength;
	if (swkbdInternalState->maxTextLength <= 0)
		swkbdInternalState->maxTextLength = SWKBD_FORM_STRING_MAX_LENGTH - 1;
	else
		swkbdInternalState->maxTextLength = std::min(swkbdInternalState->maxTextLength, SWKBD_FORM_STRING_MAX_LENGTH - 1);
	// setup initial string
	uint16be* initialString = appearArg->initialText.GetPtr();
	if (initialString)
	{
		swkbdInternalState->formStringLength = 0;
		for (sint32 i = 0; i < swkbdInternalState->maxTextLength; i++)
		{
			wchar_t c = (uint16)initialString[i];
			if( c == '\0' )
				break;
			swkbdInternalState->formStringBuffer[i] = c;
			swkbdInternalState->formStringLength++;
		}
		swkbdInternalState->formStringBuffer[swkbdInternalState->formStringLength] = L'\0';
	}
	else
	{
		swkbdInternalState->formStringBuffer[0] = L'\0';
		swkbdInternalState->formStringLength = 0;
	}
	// Apply cursorIndex from AppearArg, matching the firmware's clamping exactly
	// (confirmed by disasm of sub_020a18d0 in swkbd.rpl):
	//   if cursorIndex in [0, stringLength] → use as-is
	//   if cursorIndex < 0 or > stringLength → clamp to stringLength (end)
	{
		const sint32 argCursor = (sint32)(uint32)appearArg->cursorIndex;
		const sint32 strLen    = swkbdInternalState->formStringLength;
		swkbdInternalState->cursorPos = (argCursor >= 0 && argCursor <= strLen) ? argCursor : strLen;
	}
	// Copy the optional info label (shown above the input field).
	{
		const uint16be* infoStr = appearArg->hintText.GetPtr();
		if (infoStr)
		{
			sint32 i = 0;
			for (; i < 255; i++)
			{
				const wchar_t c = (uint16)infoStr[i];
				swkbdInternalState->infoTextBuffer[i] = c;
				if (c == L'\0')
					break;
			}
			swkbdInternalState->infoTextBuffer[i] = L'\0';
		}
		else
		{
			swkbdInternalState->infoTextBuffer[0] = L'\0';
		}
	}
	osLib_returnFromFunction(hCPU, 1);
}

void swkbdExport_SwkbdAppearKeyboard(PPCInterpreter_t* hCPU)
{
	// todo: Figure out what the difference between AppearInputForm and AppearKeyboard is?
	cemuLog_logDebug(LogType::Force, "SwkbdAppearKeyboard__3RplFRCQ3_2nn5swkbd11KeyboardArg");
	SwkbdKeyboardArg_t* keyboardArg = (SwkbdKeyboardArg_t*)memory_getPointerFromVirtualOffset(hCPU->gpr[3]);
	// All SwkbdKeyboardArg_t fields are plain uint32 in PPC (BE) memory — swap before logging.
	#define SWP(f) _swapEndianU32((f))
	cemuLog_log(LogType::Force,
	    "SWKBD AppearKeyboard: ukn000={:08x} controllerType={:08x} keyboardMode={:08x} ukn00C={:08x}",
	    SWP(keyboardArg->ukn000), SWP(keyboardArg->controllerType),
	    SWP(keyboardArg->keyboardMode), SWP(keyboardArg->ukn00C));
	cemuLog_log(LogType::Force,
	    "SWKBD KB ukn010-01C: {:08x} {:08x} {:08x} {:08x}",
	    SWP(keyboardArg->ukn010), SWP(keyboardArg->ukn014),
	    SWP(keyboardArg->ukn018), SWP(keyboardArg->ukn01C));
	cemuLog_log(LogType::Force,
	    "SWKBD KB ukn020[]: {:08x} {:08x} {:08x} {:08x}",
	    SWP(keyboardArg->ukn020[0]), SWP(keyboardArg->ukn020[1]),
	    SWP(keyboardArg->ukn020[2]), SWP(keyboardArg->ukn020[3]));
	cemuLog_log(LogType::Force,
	    "SWKBD KB ukn030[]: {:08x} {:08x} {:08x} {:08x}",
	    SWP(keyboardArg->ukn030[0]), SWP(keyboardArg->ukn030[1]),
	    SWP(keyboardArg->ukn030[2]), SWP(keyboardArg->ukn030[3]));
	cemuLog_log(LogType::Force,
	    "SWKBD KB ukn040[]: {:08x} {:08x} {:08x} {:08x}",
	    SWP(keyboardArg->ukn040[0]), SWP(keyboardArg->ukn040[1]),
	    SWP(keyboardArg->ukn040[2]), SWP(keyboardArg->ukn040[3]));
	cemuLog_log(LogType::Force,
	    "SWKBD KB ukn050[]: {:08x} {:08x} {:08x} {:08x}",
	    SWP(keyboardArg->ukn050[0]), SWP(keyboardArg->ukn050[1]),
	    SWP(keyboardArg->ukn050[2]), SWP(keyboardArg->ukn050[3]));
	cemuLog_log(LogType::Force,
	    "SWKBD KB ukn060[]: {:08x} {:08x} {:08x} {:08x}",
	    SWP(keyboardArg->ukn060[0]), SWP(keyboardArg->ukn060[1]),
	    SWP(keyboardArg->ukn060[2]), SWP(keyboardArg->ukn060[3]));
	cemuLog_log(LogType::Force,
	    "SWKBD KB ukn070[]: {:08x} {:08x} {:08x} {:08x}",
	    SWP(keyboardArg->ukn070[0]), SWP(keyboardArg->ukn070[1]),
	    SWP(keyboardArg->ukn070[2]), SWP(keyboardArg->ukn070[3]));
	cemuLog_log(LogType::Force,
	    "SWKBD KB ukn080[]: {:08x} {:08x} {:08x} {:08x}",
	    SWP(keyboardArg->ukn080[0]), SWP(keyboardArg->ukn080[1]),
	    SWP(keyboardArg->ukn080[2]), SWP(keyboardArg->ukn080[3]));
	cemuLog_log(LogType::Force,
	    "SWKBD KB ukn090[]: {:08x} {:08x} {:08x} {:08x}",
	    SWP(keyboardArg->ukn090[0]), SWP(keyboardArg->ukn090[1]),
	    SWP(keyboardArg->ukn090[2]), SWP(keyboardArg->ukn090[3]));
	cemuLog_log(LogType::Force,
	    "SWKBD KB ukn0A0={:08x} ukn0A4={:08x}  "
	    "receiverArg: IEventReceiver={:08x} stringBuf={:08x} stringBufSize={} fixedCharLimit={} cursorPos={} selectFrom={}",
	    SWP(keyboardArg->ukn0A0), SWP(keyboardArg->ukn0A4),
	    keyboardArg->receiverArg.IEventReceiver.GetMPTR(),
	    keyboardArg->receiverArg.stringBuf.GetMPTR(),
	    (sint32)keyboardArg->receiverArg.stringBufSize,
	    (sint32)keyboardArg->receiverArg.fixedCharLimit,
	    (sint32)keyboardArg->receiverArg.cursorPos,
	    (sint32)keyboardArg->receiverArg.selectFrom);
	#undef SWP

	swkbd_beginSession(true);
	// beginSession already zeroes inputType/okButtonMode/disableKeyGroup/inputFormType.
	// AppearKeyboard only needs full-width (QWERTY) and the keyboard arg copy.
	swkbdInternalState->fullWidthMode = 1; // AppearKeyboard has no fullWidthMode; default to full-width (QWERTY)
	swkbdInternalState->keyboardArg   = *keyboardArg;
	osLib_returnFromFunction(hCPU, 1);
}

static void swkbd_deactivate(PPCInterpreter_t* hCPU, const char* name)
{
	debug_printf("%s LR: %08x\n", name, hCPU->spr.LR);
	swkbdInternalState->isActive = false;
	osLib_returnFromFunction(hCPU, 1);
}

void swkbdExport_SwkbdDisappearInputForm(PPCInterpreter_t* hCPU)
{
	swkbd_deactivate(hCPU, "SwkbdDisappearInputForm__3RplFv");
}

void swkbdExport_SwkbdDisappearKeyboard(PPCInterpreter_t* hCPU)
{
	swkbd_deactivate(hCPU, "SwkbdDisappearKeyboard__3RplFv");
}

void swkbdExport_SwkbdGetInputFormString(PPCInterpreter_t* hCPU)
{
	for(sint32 i=0; i<swkbdInternalState->formStringLength; i++)
	{
		swkbdInternalState->formStringBufferBE[i] = _swapEndianU16(swkbdInternalState->formStringBuffer[i]);
	}
	swkbdInternalState->formStringBufferBE[swkbdInternalState->formStringLength] = '\0';
	osLib_returnFromFunction(hCPU, memory_getVirtualOffsetFromPointer(swkbdInternalState->formStringBufferBE));
}

void swkbdExport_SwkbdIsDecideOkButton(PPCInterpreter_t* hCPU)
{
	// Real firmware signature: bool SwkbdIsDecideOkButton(bool* pDecided)
	// Returns decided state AND writes it to *pDecided if the pointer is non-null
	// (firmware does null-check r4 before the store).
	const bool decided = swkbdInternalState->decideButtonWasPressed;
	const MPTR pDecided = hCPU->gpr[3];
	if (pDecided)
		memory_writeU8(pDecided, decided ? 1 : 0);
	osLib_returnFromFunction(hCPU, decided ? 1 : 0);
}

void swkbdExport_SwkbdIsDecideCancelButton(PPCInterpreter_t* hCPU)
{
	// Real firmware signature: bool SwkbdIsDecideCancelButton(bool* pDecided)
	// Returns decided state AND writes it to *pDecided.
	// Note: firmware does NOT null-check the pointer before writing (unlike IsDecideOkButton).
	const bool decided = swkbdInternalState->cancelButtonWasPressed;
	const MPTR pDecided = hCPU->gpr[3];
	if (pDecided)
		memory_writeU8(pDecided, decided ? 1 : 0);
	osLib_returnFromFunction(hCPU, decided ? 1 : 0);
}

void swkbdExport_SwkbdSetEnableOkButton(PPCInterpreter_t* hCPU)
{
	// Real firmware stores !bool to instance+0x12c (disabled flag) and 1 to +0x12e (override-active).
	const bool enabled = hCPU->gpr[3] != 0;
	swkbdInternalState->okButtonHasOverride        = true;
	swkbdInternalState->okButtonDisabledByOverride = !enabled;
	osLib_returnFromFunction(hCPU, 0);
}

typedef struct  
{
	uint32be ukn00;
	uint32be ukn04;
	uint32be ukn08;
	uint32be ukn0C;
	uint32be ukn10;
	uint32be ukn14;
	uint8 ukn18;
	// there might be padding here?
}SwkbdDrawStringInfo_t;

static_assert(sizeof(SwkbdDrawStringInfo_t) != 0x19, "SwkbdDrawStringInfo_t has invalid size");

void swkbdExport_SwkbdGetDrawStringInfo(PPCInterpreter_t* hCPU)
{
	cemuLog_logDebug(LogType::Force, "SwkbdGetDrawStringInfo(0x{:08x})", hCPU->gpr[3]);
	ppcDefineParamStructPtr(drawStringInfo, SwkbdDrawStringInfo_t, 0);

	drawStringInfo->ukn00 = -1;
	drawStringInfo->ukn04 = -1;
	drawStringInfo->ukn08 = -1;
	drawStringInfo->ukn0C = -1;
	drawStringInfo->ukn10 = -1;
	drawStringInfo->ukn14 = -1;
	drawStringInfo->ukn18 = 0;

	osLib_returnFromFunction(hCPU, 0);
}

void swkbdExport_SwkbdInitLearnDic(PPCInterpreter_t* hCPU)
{
	cemuLog_logDebug(LogType::Force, "SwkbdInitLearnDic(0x{:08x})", hCPU->gpr[3]);
	// todo

	// this has to fail (at least once?) or MH3U will not boot
	osLib_returnFromFunction(hCPU, 1);
}

void swkbdExport_SwkbdIsNeedCalcSubThreadFont(PPCInterpreter_t* hCPU)
{
	osLib_returnFromFunction(hCPU, 0);
}

void swkbdExport_SwkbdIsNeedCalcSubThreadPredict(PPCInterpreter_t* hCPU)
{
	osLib_returnFromFunction(hCPU, 0);
}

void swkbd_keyInput(uint32 keyCode);

// Returns true if the given printable character is accepted in the current keyboard mode.
// Used both to gate swkbd_keyInput and to grey out buttons in the UI.
static bool swkbd_isCharAllowed(uint32 keyCode)
{
	if (keyCode < 32 || keyCode >= 128)
		return false;

	// Half-width + alphabetic group (bit 15) → numpad mode: digits only.
	// This is the confirmed disableKeyGroup behaviour: the numpad layout is
	// triggered by fullWidthMode==0 combined with bit 15.
	// Note: disableKeyGroup=0x0007FFFF (all valid bits set) is used by games
	// like the eShop to mean "show all groups" and does NOT disable characters.
	if (swkbdInternalState->fullWidthMode == 0 && (swkbdInternalState->disableKeyGroup & (1u << 15)))
		return keyCode >= '0' && keyCode <= '9';

	// NOTE on per-character restrictions (e.g. eShop disabling I/O/Z):
	// Disassembly of swkbd.rpl shows the keyboard layout is fully data-driven from
	// a master pointer table in .data (0x10049fbc): groups of 6 layout-string
	// pointers (symbols / lower / upper / upper-alt / num / num) selected by the
	// language + keyboard-type. There is NO generic per-inputType character-disable
	// path — inputType=1 is a common layout-selector value used by many ordinary
	// dialogs (including the folder-name keyboard, which accepts all characters).
	// Replicating the eShop's restricted set would require reproducing that whole
	// layout table; until then we show the full QWERTY layout (the accurate default
	// for the vast majority of titles).
	return true;
}

// Single source of truth for whether the OK/confirm button is currently enabled.
// Called from both the render code (to grey the key) and swkbd_finishInput (to gate confirm).
//
// Real firmware logic (from swkbd.rpl disasm):
//   okMode 0 = normal:        enabled when textLen >= minTextLength (default 1)
//   okMode 1 = enterPress:    same threshold as mode 0 (require at least 1 char)
//   okMode 2 = disabled:      always disabled
//   okMode 3 = always-on:     enabled even with 0 chars (confirmed as 0..3 enum, ≥4→0)
// Additionally, SwkbdSetEnableOkButton() overrides all of the above.
static bool swkbd_isOkButtonEnabled()
{
	// Game-set override takes precedence over everything.
	if (swkbdInternalState->okButtonHasOverride)
		return !swkbdInternalState->okButtonDisabledByOverride;

	const uint32 okMode = swkbdInternalState->okButtonMode;
	if (okMode == 2) return false;
	if (okMode == 3) return true;
	// Modes 0 and 1: enabled when text meets the minimum length.
	return swkbdInternalState->formStringLength >= swkbdInternalState->minTextLength;
}

// ── Key layout tables ─────────────────────────────────────────────────────────
// Defined at file scope so both the render loop and the controller nav code
// share the same arrays — no duplication, no risk of the two getting out of sync.

static const char* kNormalKeys[] =
{
	"1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", _utf8WrapperPtr(ICON_FA_ARROW_CIRCLE_LEFT), "\n",
	"q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "/", "\n",
	"a", "s", "d", "f", "g", "h", "j", "k", "l", ":", "'", "\n",
	"z", "x", "c", "v", "b", "n", "m", ",", ".", "?", "!", "\n",
	_utf8WrapperPtr(ICON_FA_TIMES), _utf8WrapperPtr(ICON_FA_ARROW_UP), " ", _utf8WrapperPtr(ICON_FA_CHECK)
};
static const char* kShiftedKeys[] =
{
	"#", "[", "]", "$", "%", "^", "&", "*", "(", ")", "_", _utf8WrapperPtr(ICON_FA_ARROW_CIRCLE_LEFT), "\n",
	"Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P", "@", "\n",
	"A", "S", "D", "F", "G", "H", "J", "K", "L", ";", "\"", "\n",
	"Z", "X", "C", "V", "B", "N", "M", "<", ">", "+", "=", "\n",
	_utf8WrapperPtr(ICON_FA_TIMES), _utf8WrapperPtr(ICON_FA_ARROW_UP), " ", _utf8WrapperPtr(ICON_FA_CHECK)
};
// Numpad: rows are 1-2-3-⌫ / 4-5-6 / 7-8-9 / ·-0-· / ×-spc-✓
// "" = visible disabled spacer used to visually balance the "0" row.
static const char* kNumpadKeys[] =
{
	"1", "2", "3", _utf8WrapperPtr(ICON_FA_ARROW_CIRCLE_LEFT), "\n",
	"4", "5", "6",                                              "\n",
	"7", "8", "9",                                              "\n",
	"",  "0", "",                                               "\n",
	_utf8WrapperPtr(ICON_FA_TIMES), " ", _utf8WrapperPtr(ICON_FA_CHECK)
};

// Row-start indices into each flat array (accounts for '\n' separators).
static constexpr int kQwertyRowStart[] = { 0, 13, 25, 37, 49 };
static constexpr int kNumpadRowStart[] = { 0,  5,  9, 13, 17 };

// Activate the action for a key string — used by both the mouse-click path
// and the controller A-button path so the logic lives in exactly one place.
static void swkbd_activateKey(const char* key)
{
	if      (strcmp(key, _utf8WrapperPtr(ICON_FA_TIMES)) == 0)             swkbdInternalState->cancelButtonWasPressed = true;
	else if (strcmp(key, _utf8WrapperPtr(ICON_FA_ARROW_CIRCLE_LEFT)) == 0) swkbd_keyInput(8);
	else if (strcmp(key, _utf8WrapperPtr(ICON_FA_ARROW_UP)) == 0)          swkbdInternalState->shiftActivated = !swkbdInternalState->shiftActivated;
	else if (strcmp(key, _utf8WrapperPtr(ICON_FA_CHECK)) == 0)             swkbd_keyInput(13);
	else                                                                    swkbd_keyInput((uint8)*key);
}


void swkbd_render(bool mainWindow)
{
	// Animation state: separate timers for appear and disappear.
	// Shared statics so both the main window and GamePad window use the same timestamps.
	static std::chrono::steady_clock::time_point s_appear_time;
	static std::chrono::steady_clock::time_point s_disappear_time;
	static bool s_was_active   = false;
	static bool s_disappearing = false;

	const bool nowActive = (swkbdInternalState != NULL && swkbdInternalState->isActive);
	const auto now = tick_cached(); // single clock read for the whole frame

	if (nowActive && !s_was_active)
	{
		// Keyboard just appeared — start fade-in, cancel any in-progress fade-out.
		s_appear_time  = now;
		s_disappearing = false;
	}
	else if (!nowActive && s_was_active)
	{
		// Keyboard just dismissed — start fade-out.
		s_disappear_time = now;
		s_disappearing   = true;
	}
	s_was_active = nowActive;

	constexpr float kAnimDuration = 0.25f;

	if (s_disappearing)
	{
		if (std::chrono::duration<float>(now - s_disappear_time).count() >= kAnimDuration)
		{
			s_disappearing = false;
			return; // fade-out complete
		}
	}
	else if (!nowActive)
	{
		return; // inactive and no fade-out pending
	}

	// eased: 0→1 while appearing (ease-out), 1→0 while disappearing (ease-in).
	// The slide formula  40*(1-eased)  reverses automatically:
	//   appearing    → offset 40→0  (slides up)
	//   disappearing → offset 0→40  (slides down)
	const float eased = [&]()
	{
		if (s_disappearing)
		{
			const float t = std::min(std::chrono::duration<float>(now - s_disappear_time).count() / kAnimDuration, 1.0f);
			return (1.0f - t) * (1.0f - t); // fast exit, gentle finish
		}
		const float t = std::min(std::chrono::duration<float>(now - s_appear_time).count() / kAnimDuration, 1.0f);
		return 1.0f - (1.0f - t) * (1.0f - t); // fast rise, gentle finish
	}();

	auto& io = ImGui::GetIO();

	// ── Canvas ────────────────────────────────────────────────────────────────
	// Resolve first — before any Push/Pop — so an early return never leaves the
	// style stack unbalanced, and so font sizes can be derived from canvas height.
	sint32 canvasX, canvasY, canvasW, canvasH;
	LatteRenderTarget_getScreenImageArea(&canvasX, &canvasY, &canvasW, &canvasH, nullptr, nullptr, !mainWindow);
	if (canvasW <= 0 || canvasH <= 0)
		return; // canvas not ready yet
	const ImVec2 canvasMin = { (float)canvasX, (float)canvasY };
	const float cW = (float)canvasW;
	const float cH = (float)canvasH;

	// ── Global scale ──────────────────────────────────────────────────────────
	// Everything is authored at a 1280×720 baseline and scaled from there.
	const float scale = cH / 720.0f;

	// ── Font ──────────────────────────────────────────────────────────────────
	// One atlas entry at a fixed base size; per-window vertex scaling via
	// SetWindowFontScale() gives any target size without atlas rebuilds.
	// Base 64 px: downscales cleanly to 720p/1080p, slight upscale at 4K.
	// All UI elements render at 52 px equivalent at 720p.
	constexpr float kBaseFontSz = 64.0f;
	const auto baseFont = ImGui_GetFont(kBaseFontSz);
	if (!baseFont)
		return; // font queued for loading; renders correctly next frame
	// Per-element scales: base-size-at-720p × resolution-scale ÷ atlas-font-size.
	const float uiScaleKeys  = (swkbd_fontSizeKeys  * scale) / kBaseFontSz;
	const float uiScaleHint  = (swkbd_fontSizeHint  * scale) / kBaseFontSz;
	const float uiScaleInput = (swkbd_fontSizeInput * scale) / kBaseFontSz;

	// ── Layout metrics ────────────────────────────────────────────────────────
	const auto& style    = ImGui::GetStyle();
	const float kWinPadX = style.WindowPadding.x;
	const float kWinPadY = style.WindowPadding.y;
	const float kItemSpX = style.ItemSpacing.x;
	const float kItemSpY = style.ItemSpacing.y;
	const float kFramePadY = style.FramePadding.y;
	const float kInnerW  = cW - kWinPadX * 2.0f;
	// 12 keys fill the full canvas width (widest row: digits + backspace).
	const float keyWidth   = (kInnerW - kItemSpX * 11.0f) / 12.0f;
	// Space bar fills what remains after back, shift, and enter on the bottom row.
	const float spaceWidth = kInnerW - keyWidth * 3.0f - kItemSpX * 3.0f;
	// Five rows + four gaps + top/bottom padding = exactly cH/2.
	const float keyHeight  = (cH * 0.5f - 4.0f * kItemSpY - 2.0f * kWinPadY) / 5.0f;
	// Slide animation offset scales with the canvas so it feels the same at every resolution.
	const float slideOffset = 40.0f * scale * (1.0f - eased);

	const auto kPopupFlags = ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoNav;

	// ── Global style pushes ───────────────────────────────────────────────────
	ImGui::PushStyleColor(ImGuiCol_WindowBg, 0);
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, eased);

	// Background dim — only shown in input-form mode; keyboard-only mode draws over the game directly.
	if (!swkbdInternalState->keyboardOnlyMode)
	{
		ImGui::SetNextWindowPos(canvasMin, ImGuiCond_Always);
		ImGui::SetNextWindowSize({ cW, cH }, ImGuiCond_Always);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, { 0,0 });
		ImGui::SetNextWindowBgAlpha(0.8f * eased);
		ImGui::Begin("Background overlay", nullptr, kPopupFlags | ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoBringToFrontOnFocus);
		ImGui::End();
		ImGui::PopStyleVar(2);
	}

	// Layout metrics for small-field mode (centred in the upper quarter).
	const float anchorY    = canvasMin.y + cH * 0.25f;
	const float fieldWidth = cW * 0.8f;
	// Estimated single-line height of the input box (font + padding).
	const float inputH      = swkbd_fontSizeInput * scale + 2.0f * kWinPadY + 2.0f * kFramePadY;
	// Info text uses a bottom pivot so multi-line text grows upward, never
	// overlapping the input field below it.
	const float infoBottomY = anchorY - inputH * 0.5f - 6.0f * scale;

	// Large-field mode (inputFormType 1): the input box fills the entire top half and
	// renders the hint text as an inline grey placeholder instead of a separate label.
	const bool isLargeField = (!swkbdInternalState->keyboardOnlyMode && swkbdInternalState->inputFormType == 1);

	// Blink cursor — shared by both small and large field paths.
	static std::chrono::steady_clock::time_point s_last_tick = tick_cached();
	static bool s_blink_state = false;
	if (std::chrono::duration_cast<std::chrono::milliseconds>(now - s_last_tick).count() >= 500)
	{
		s_blink_state = !s_blink_state;
		s_last_tick = now;
	}

	// Info label — only shown in small-field mode; large-field uses inline placeholder.
	if (!isLargeField && swkbdInternalState->infoTextBuffer[0] != L'\0')
	{
		const auto infoStr = boost::nowide::narrow(swkbdInternalState->infoTextBuffer);
		ImGui::SetNextWindowBgAlpha(0.0f);
		ImGui::SetNextWindowSizeConstraints({ fieldWidth, 0.0f }, { fieldWidth, FLT_MAX });
		ImGui::SetNextWindowPos({ canvasMin.x + cW * 0.5f, infoBottomY },
		                        ImGuiCond_Always, { 0.5f, 1.0f });
		ImGui::PushFont(baseFont);
		if (ImGui::Begin("Keyboard Info Label", nullptr, kPopupFlags | ImGuiWindowFlags_NoBackground))
		{
			ImGui::SetWindowFontScale(uiScaleHint);
			const float windowW = ImGui::GetWindowWidth();
			const float wrapW   = windowW - 2.0f * kWinPadX;
			auto flushLine = [&](const std::string& line)
			{
				if (line.empty())
					return;
				const float lineW = ImGui::CalcTextSize(line.c_str()).x;
				ImGui::SetCursorPosX((windowW - lineW) * 0.5f);
				ImGui::TextUnformatted(line.c_str());
			};

			std::string currentLine;
			const char* p = infoStr.c_str();
			while (*p)
			{
				const char* wordStart = p;
				while (*p && *p != ' ')
					++p;
				std::string word(wordStart, p);
				if (*p == ' ')
					++p;
				std::string testLine = currentLine.empty() ? word : currentLine + ' ' + word;
				if (!currentLine.empty() && ImGui::CalcTextSize(testLine.c_str()).x > wrapW)
				{
					flushLine(currentLine);
					currentLine = std::move(word);
				}
				else
				{
					currentLine = std::move(testLine);
				}
			}
			flushLine(currentLine);
		}
		ImGui::End();
		ImGui::PopFont();
	}

	// Input box — only shown when there is an input form (not keyboard-only mode).
	if (!swkbdInternalState->keyboardOnlyMode)
	{
		ImGui::PushFont(baseFont);
		if (isLargeField)
		{
			// Large field: fill the entire top half of the canvas with no auto-resize.
			constexpr auto kLargeFieldFlags = ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoDecoration |
			                                  ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoNav |
			                                  ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar;
			ImGui::SetNextWindowPos(canvasMin, ImGuiCond_Always, { 0.0f, 0.0f });
			ImGui::SetNextWindowSize({ cW, cH * 0.5f }, ImGuiCond_Always);
			ImGui::SetNextWindowBgAlpha(0.9f * eased);
			if (ImGui::Begin("Keyboard Input", nullptr, kLargeFieldFlags))
			{
				ImGui::SetWindowFontScale(uiScaleInput);
				ImGui::PushTextWrapPos();
				if (swkbdInternalState->formStringLength == 0 && swkbdInternalState->infoTextBuffer[0] != L'\0')
				{
					// Hint text as grey placeholder — cursor position is unaffected.
					const auto hintStr = boost::nowide::narrow(swkbdInternalState->infoTextBuffer);
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.55f, 0.55f, 1.0f));
					ImGui::TextUnformatted(hintStr.c_str());
					ImGui::PopStyleColor();
				}
				else
				{
					auto text = boost::nowide::narrow(swkbdInternalState->formStringBuffer);
					if (s_blink_state)
					{
						// cursorPos is a wchar_t character index; narrow only the prefix
						// to get the correct UTF-8 byte offset (matters for non-ASCII initialText).
						const sint32 charPos = std::clamp(swkbdInternalState->cursorPos, 0, swkbdInternalState->formStringLength);
						const size_t bytePos = boost::nowide::narrow(
							std::wstring(swkbdInternalState->formStringBuffer, (size_t)charPos)).size();
						text.insert(bytePos, "|");
					}
					ImGui::TextUnformatted(text.c_str(), text.c_str() + text.size());
				}
				ImGui::PopTextWrapPos();
			}
			ImGui::End();
		}
		else
		{
			// Small field: centred in the upper quarter of the canvas.
			ImGui::SetNextWindowSizeConstraints({ fieldWidth, 0.0f }, { fieldWidth, FLT_MAX });
			ImGui::SetNextWindowPos({ canvasMin.x + cW * 0.5f, anchorY },
			                        ImGuiCond_Always, { 0.5f, 0.5f });
			ImGui::SetNextWindowBgAlpha(0.9f * eased);
			if (ImGui::Begin("Keyboard Input", nullptr, kPopupFlags))
			{
				ImGui::SetWindowFontScale(uiScaleInput);
				ImGui::Text("%s", _utf8WrapperPtr(ICON_FA_KEYBOARD));
				ImGui::SameLine(0, 8);
				auto text = boost::nowide::narrow(swkbdInternalState->formStringBuffer);
				if (s_blink_state)
				{
					const sint32 charPos = std::clamp(swkbdInternalState->cursorPos, 0, swkbdInternalState->formStringLength);
					const size_t bytePos = boost::nowide::narrow(
						std::wstring(swkbdInternalState->formStringBuffer, (size_t)charPos)).size();
					text.insert(bytePos, "|");
				}
				ImGui::PushTextWrapPos();
				ImGui::TextUnformatted(text.c_str(), text.c_str() + text.size());
				ImGui::PopTextWrapPos();
			}
			ImGui::End();
		}
		ImGui::PopFont();
	}

	// Half-width + alphabetic group disabled → numpad layout.
	// Computed once here; used by both the key render loop and the nav input block.
	const bool isNumpad = (swkbdInternalState->fullWidthMode == 0 && (swkbdInternalState->disableKeyGroup & (1u << 15)) != 0);

	// Keyboard — bottom-centre pivot at canvas bottom; slides in/out via slideOffset.
	ImGui::SetNextWindowSizeConstraints({ cW, 0.0f }, { cW, FLT_MAX });
	ImGui::SetNextWindowPos({ canvasMin.x + cW * 0.5f, canvasMin.y + cH + slideOffset },
	                        ImGuiCond_Always, { 0.5f, 1.0f });
	ImGui::SetNextWindowBgAlpha(0.9f * eased);
	ImGui::PushFont(baseFont);

	if (ImGui::Begin(mainWindow ? "Software keyboard##SoftwareKeyboard1" : "Software keyboard##SoftwareKeyboard0", nullptr, kPopupFlags))
	{
		ImGui::SetWindowFontScale(uiScaleKeys);

		// Shared key-drawing helper: applies disabled greying, nav highlight, and
		// click→activate.  Positioning/layout is the caller's responsibility.
		// Faithful extraction of the per-key logic so all layouts behave identically.
		auto drawKey = [&](const char* key, float btnW, int rowIdx, int colIdx)
		{
			const bool isIconKey      = (*key & 0x80) != 0; // FontAwesome uses high-byte codepoints
			const bool isOkKey        = strcmp(key, _utf8WrapperPtr(ICON_FA_CHECK)) == 0;
			const bool isBackspaceKey = strcmp(key, _utf8WrapperPtr(ICON_FA_ARROW_CIRCLE_LEFT)) == 0;
			const bool isDisabled = (!isIconKey && !swkbd_isCharAllowed((uint8)*key))
			                     || (isOkKey        && !swkbd_isOkButtonEnabled())
			                     || (isBackspaceKey && swkbdInternalState->formStringLength == 0);
			const bool navSel = !isDisabled && (rowIdx == swkbdInternalState->navRow && colIdx == swkbdInternalState->navCol);
			int stylePushCount = 0;
			if (isDisabled)
			{
				ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.20f, 0.20f, 0.20f, 0.60f));
				ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.20f, 0.20f, 0.20f, 0.60f));
				ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.20f, 0.20f, 0.20f, 0.60f));
				ImGui::PushStyleColor(ImGuiCol_Text,          ImVec4(0.40f, 0.40f, 0.40f, 1.00f));
				stylePushCount = 4;
			}
			else if (navSel)
			{
				ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.20f, 0.50f, 0.90f, 1.00f));
				ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.30f, 0.60f, 1.00f, 1.00f));
				ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.10f, 0.40f, 0.80f, 1.00f));
				stylePushCount = 3;
			}
			ImGui::Button(key, { btnW, keyHeight });
			const bool triggered = !isDisabled && ImGui::IsItemClicked();
			if (stylePushCount > 0)
				ImGui::PopStyleColor(stylePushCount);
			if (triggered)
				swkbd_activateKey(key);
		};

		const char* const* keys;
		size_t keyCount;
		if (isNumpad)
		{
			keys     = kNumpadKeys;
			keyCount = std::size(kNumpadKeys);
		}
		else
		{
			keys     = swkbdInternalState->shiftActivated ? kShiftedKeys : kNormalKeys;
			keyCount = swkbdInternalState->shiftActivated ? std::size(kShiftedKeys) : std::size(kNormalKeys);
		}

		// Numpad: key width sized for 3 columns at 40% of canvas.
		// Each row is independently centred based on its actual key count.
		const float numpadKeyW = (cW * 0.40f - kItemSpX * 2.0f) / 3.0f;
		const float numpadSpcW = numpadKeyW;
		static constexpr int kNumpadRowKeyCounts[] = { 3, 3, 3, 3, 3 };
		const auto numpadRowIndentX = [&](int r) {
			const int n = kNumpadRowKeyCounts[r];
			return (ImGui::GetWindowWidth() - (numpadKeyW * n + kItemSpX * (n - 1))) * 0.5f;
		};

		// Start the first row at the centred position.
		if (isNumpad)
			ImGui::SetCursorPosX(numpadRowIndentX(0));

		int curRow = 0, curCol = 0;
		for (size_t ki = 0; ki < keyCount; ki++)
		{
			const char* key = keys[ki];
			if (*key == '\n')
			{
				curRow++;
				curCol = 0;
				ImGui::NewLine();
				if (isNumpad)
					ImGui::SetCursorPosX(numpadRowIndentX(curRow));
				continue;
			}
			const float btnW = isNumpad
				? (*key == ' ' ? numpadSpcW : numpadKeyW)
				: (*key == ' ' ? spaceWidth : keyWidth);
			drawKey(key, btnW, curRow, curCol);
			ImGui::SameLine();
			curCol++;
		}
		ImGui::NewLine();
	}
	ImGui::End();

	// Nav inputs are processed only for the main window.  Both the main and pad
	// windows call swkbd_render each frame with separate ImGui contexts.  If both
	// contexts ran this block, the pad call would reset cancelState/returnState to
	// false even while the main-window Cancel/Input nav is still held, causing the
	// main call to fire backspace or confirm on every single frame and immediately
	// erase any character the user just typed.
	if (mainWindow)
	{
		// Snapshot every NavInput we use, then zero them out immediately.
		// io.NavInputs values are only ever SET by the input layer (never cleared),
		// so without this they persist at 1.0f after a button is released, causing
		// all edge-detection to get permanently stuck after the first press.
		const float axisLeft      = io.NavInputs[ImGuiNavInput_DpadLeft];
		const float axisRight     = io.NavInputs[ImGuiNavInput_DpadRight];
		const float axisUp        = io.NavInputs[ImGuiNavInput_DpadUp];
		const float axisDown      = io.NavInputs[ImGuiNavInput_DpadDown];
		const float axisActivate  = io.NavInputs[ImGuiNavInput_Activate];
		const float axisCancel    = io.NavInputs[ImGuiNavInput_Cancel];
		const float axisInput     = io.NavInputs[ImGuiNavInput_Input];
		const float axisShoulderL = io.NavInputs[ImGuiNavInput_FocusPrev];
		const float axisShoulderR = io.NavInputs[ImGuiNavInput_FocusNext];
		const float axisLStickClick = io.NavInputs[ImGuiNavInput_TweakSlow];
		io.NavInputs[ImGuiNavInput_DpadLeft]  = 0.f;
		io.NavInputs[ImGuiNavInput_DpadRight] = 0.f;
		io.NavInputs[ImGuiNavInput_DpadUp]    = 0.f;
		io.NavInputs[ImGuiNavInput_DpadDown]  = 0.f;
		io.NavInputs[ImGuiNavInput_Activate]  = 0.f;
		io.NavInputs[ImGuiNavInput_Cancel]    = 0.f;
		io.NavInputs[ImGuiNavInput_Input]     = 0.f;
		io.NavInputs[ImGuiNavInput_FocusPrev] = 0.f;
		io.NavInputs[ImGuiNavInput_FocusNext] = 0.f;
		io.NavInputs[ImGuiNavInput_TweakSlow] = 0.f;

		// While the fade-in animation is still running, only update the held-state
		// trackers without firing any actions.  This ensures that a button held to
		// open the keyboard is already marked as "held" by the time the animation
		// completes, so the rising-edge check suppresses it correctly.
		if (s_disappearing || eased < 1.0f)
		{
			uint8 currDirs = 0;
			if (axisLeft  > 0.5f) currDirs |= 1;
			if (axisRight > 0.5f) currDirs |= 2;
			if (axisUp    > 0.5f) currDirs |= 4;
			if (axisDown  > 0.5f) currDirs |= 8;
			swkbdInternalState->navHeldDirs  = currDirs;
			swkbdInternalState->activateHeld    = axisActivate  > 0.5f;
			swkbdInternalState->cancelState     = axisCancel    > 0.5f;
			swkbdInternalState->returnState     = axisInput     > 0.5f;
			swkbdInternalState->shoulderLHeld   = axisShoulderL   > 0.5f;
			swkbdInternalState->shoulderRHeld   = axisShoulderR   > 0.5f;
			swkbdInternalState->lstickHeld      = axisLStickClick > 0.5f;
		}
		else
		{

		// ── D-pad: edge-triggered grid navigation ────────────────────────────
		// Row sizes differ between QWERTY and numpad layouts.
		// Numpad rows: 4 / 3 / 3 / 3 / 3  (1-2-3-⌫ / 4-5-6 / 7-8-9 / ·-0-· / ×-spc-✓)
		// Disabled cells are skipped automatically by isNavCellDisabled below.
		static constexpr int kQwertyRowSizes[] = { 12, 11, 11, 11, 4 };
		static constexpr int kNumpadRowSizes[] = {  4,  3,  3,  3, 3 };
		const int* kRowSizes = isNumpad ? kNumpadRowSizes : kQwertyRowSizes;
		const int  kNumRows  = 5;

		int& row = swkbdInternalState->navRow;
		int& col = swkbdInternalState->navCol;

		// Resolve the key string at a (row, col) nav cell for the active layout.
		// Shared by the disabled-cell skip and the A-button activation below.
		auto navKeyAt = [&](int r, int c) -> const char* {
			if (isNumpad) return kNumpadKeys[kNumpadRowStart[r] + c];
			return (swkbdInternalState->shiftActivated ? kShiftedKeys : kNormalKeys)[kQwertyRowStart[r] + c];
		};

		uint8 currDirs = 0;
		if (axisLeft  > 0.5f) currDirs |= 1;
		if (axisRight > 0.5f) currDirs |= 2;
		if (axisUp    > 0.5f) currDirs |= 4;
		if (axisDown  > 0.5f) currDirs |= 8;

		const uint8 pressed = currDirs & ~swkbdInternalState->navHeldDirs;
		if (pressed & 1) col = (col > 0) ? col - 1 : kRowSizes[row] - 1;
		if (pressed & 2) col = (col < kRowSizes[row] - 1) ? col + 1 : 0;
		if (pressed & 4) { if (row > 0)          { --row; col = std::min(col, kRowSizes[row] - 1); } }
		if (pressed & 8) { if (row < kNumRows-1) { ++row; col = std::min(col, kRowSizes[row] - 1); } }
		swkbdInternalState->navHeldDirs = currDirs;

		// ── L/R shoulder: move the text input cursor left / right ────────────
		// In input-form mode the cursor is always visible — shoulder buttons always work.
		// In keyboard-only mode, cursor movement is disabled when the game sets fixedCharLimit >= 0
		// (fixed-slot / PIN mode: characters are appended left-to-right, no mid-string edit).
		// fixedCharLimit == -1 means free cursor even in keyboard-only mode.
		// Note: we only apply this in keyboardOnlyMode — in input-form mode fixedCharLimit
		// may be 0 from the initial memset if SwkbdSetReceiver was never called.
		const bool shoulderLNow = axisShoulderL > 0.5f;
		const bool shoulderRNow = axisShoulderR > 0.5f;
		const bool freeCursor = !swkbdInternalState->keyboardOnlyMode ||
		                        (sint32)swkbdInternalState->keyboardArg.receiverArg.fixedCharLimit < 0;
		if (freeCursor)
		{
			if (shoulderLNow && !swkbdInternalState->shoulderLHeld)
				swkbdInternalState->cursorPos = std::max(0, swkbdInternalState->cursorPos - 1);
			if (shoulderRNow && !swkbdInternalState->shoulderRHeld)
				swkbdInternalState->cursorPos = std::min(swkbdInternalState->formStringLength, swkbdInternalState->cursorPos + 1);
			if ((shoulderLNow && !swkbdInternalState->shoulderLHeld) || (shoulderRNow && !swkbdInternalState->shoulderRHeld))
				swkbdInternalState->keyboardArg.receiverArg.cursorPos = swkbdInternalState->cursorPos;
		}
		swkbdInternalState->shoulderLHeld = shoulderLNow;
		swkbdInternalState->shoulderRHeld = shoulderRNow;

		// ── L3 (left stick click): toggle shift — no-op in numpad mode ──────
		const bool lstickNow = axisLStickClick > 0.5f;
		if (lstickNow && !swkbdInternalState->lstickHeld && !isNumpad)
			swkbdInternalState->shiftActivated = !swkbdInternalState->shiftActivated;
		swkbdInternalState->lstickHeld = lstickNow;

		// ── Skip disabled character keys during d-pad navigation ─────────────
		// If the cursor landed on a greyed-out character, advance in the same
		// direction until a non-disabled key is found (wraps at row boundary).
		{
			auto isNavCellDisabled = [&]() -> bool {
				// Ask swkbd_isCharAllowed about the key at (row, col).  The same function
				// drives the visual greying in the render loop, so nav and display stay in sync.
				const char* k = navKeyAt(row, col);
				const bool isIcon = (*k & 0x80) != 0; // FontAwesome multi-byte → never disabled
				if (isIcon || *k == '\0') return false; // icons and spacers are handled separately
				if (*k == ' ') return false;             // space bar is never a char-disabled key
				return !swkbd_isCharAllowed((uint8)*k);
			};
			if (isNavCellDisabled())
			{
				// Walk in the same direction as the button that was pressed so that
				// navigating left skips left through disabled cells (and right skips right).
				// For vertical moves (up/down) default to walking right.
				const int skipDir = (pressed & 1) ? -1 : 1;
				for (int attempt = 0; attempt < kRowSizes[row]; attempt++)
				{
					if (skipDir > 0)
						col = (col < kRowSizes[row] - 1) ? col + 1 : 0;
					else
						col = (col > 0) ? col - 1 : kRowSizes[row] - 1;
					if (!isNavCellDisabled()) break;
				}
			}
		}

		// ── A: activate the highlighted key ──────────────────────────────────
		const bool activateNow = axisActivate > 0.5f;
		if (activateNow && !swkbdInternalState->activateHeld)
		{
			// Map (row, col) → key string using the shared resolver.
			swkbd_activateKey(navKeyAt(row, col));
		}
		swkbdInternalState->activateHeld = activateNow;

		// ── B: backspace ──────────────────────────────────────────────────────
		const bool cancelNow = axisCancel > 0.5f;
		if (cancelNow && !swkbdInternalState->cancelState)
			swkbd_keyInput(8);
		swkbdInternalState->cancelState = cancelNow;

		// ── Start: confirm ────────────────────────────────────────────────────
		const bool returnNow = axisInput > 0.5f;
		if (returnNow && !swkbdInternalState->returnState)
			swkbd_keyInput(13);
		swkbdInternalState->returnState = returnNow;
		} // else (animation complete)
	} // if (mainWindow)

	ImGui::PopFont();
	ImGui::PopStyleVar(); // fade-in alpha
	ImGui::PopStyleColor();
}

bool swkbd_hasKeyboardInputHook()
{
	return swkbdInternalState != NULL && swkbdInternalState->isActive;
}

void swkbd_finishInput()
{
	if (!swkbd_isOkButtonEnabled())
		return;
	swkbdInternalState->decideButtonWasPressed = true;
}

typedef struct  
{
	uint32be beginIndex;
	uint32be endIndex;
}changeStringParam_t;

SysAllocator<changeStringParam_t> _changeStringParam;

// Notify the title that the string buffer has changed.
// beginIndex/endIndex describe the dirty range in the *old* string:
//   - For a character append at position N:  beginIndex = endIndex = N  (pure insertion, nothing removed)
//   - For a backspace that removed position N: beginIndex = N, endIndex = N+1
// The title reads the new string from stringBuf and applies [beginIndex,endIndex) → [beginIndex,newLength).
void swkbd_inputStringChanged(sint32 beginIndex, sint32 endIndex)
{
	// Write the current string and cursor position to the application's receiver buffers.
	uint32 stringBufferSize = swkbdInternalState->keyboardArg.receiverArg.stringBufSize; // in 2-byte words
	if (stringBufferSize > 1)
	{
		stringBufferSize--; // exclude null terminator slot
		const auto stringBufferBE = swkbdInternalState->keyboardArg.receiverArg.stringBuf.GetPtr();
		sint32 copyLength = std::min((sint32)stringBufferSize, swkbdInternalState->formStringLength);
		for (sint32 i = 0; i < copyLength; i++)
			stringBufferBE[i] = swkbdInternalState->formStringBuffer[i];
		stringBufferBE[copyLength] = '\0';
	}
	swkbdInternalState->keyboardArg.receiverArg.cursorPos = swkbdInternalState->cursorPos;
	// Fire the IEventReceiver::changeString callback with the exact dirty range so the
	// title can apply a minimal update rather than re-inserting the whole string.
	if (swkbdInternalState->keyboardArg.receiverArg.IEventReceiver)
	{
		SwkbdIEventReceiver_t* eventReceiver = swkbdInternalState->keyboardArg.receiverArg.IEventReceiver.GetPtr();
		MPTR cbChangeString = eventReceiver->vTable->changeString.GetMPTR();
		if (cbChangeString)
		{
			changeStringParam_t* changeStringParam = _changeStringParam.GetPtr();
			changeStringParam->beginIndex = (uint32)beginIndex;
			changeStringParam->endIndex   = (uint32)endIndex;
			coreinitAsyncCallback_add(cbChangeString, 2, memory_getVirtualOffsetFromPointer(eventReceiver), _changeStringParam.GetMPTR());
		}
	}
}

void swkbd_keyInput(uint32 keyCode)
{
	if (keyCode == 8 || keyCode == 127) // backspace || backwards delete
	{
		if (swkbdInternalState->cursorPos > 0)
		{
			const sint32 delPos   = swkbdInternalState->cursorPos - 1;
			const sint32 oldLength = swkbdInternalState->formStringLength;
			// Shift everything after the deleted character one position left.
			for (sint32 i = delPos; i < oldLength - 1; i++)
				swkbdInternalState->formStringBuffer[i] = swkbdInternalState->formStringBuffer[i + 1];
			swkbdInternalState->formStringLength--;
			swkbdInternalState->cursorPos--;
			swkbdInternalState->formStringBuffer[swkbdInternalState->formStringLength] = L'\0';
			// Dirty range: character at [delPos, delPos+1) was removed.
			swkbd_inputStringChanged(delPos, delPos + 1);
		}
		return;
	}
	else if (keyCode == 13) // return
	{
		swkbd_finishInput();
		return;
	}
	// Reject control characters and any character not allowed in the current mode
	// (e.g. non-digits in numpad mode).  This gate applies to both on-screen button
	// presses and physical keyboard input.
	if (!swkbd_isCharAllowed(keyCode))
		return;
	// get max length
	sint32 maxLength = swkbdInternalState->maxTextLength;
	if (swkbdInternalState->keyboardOnlyMode)
	{
		uint32 stringBufferSize = swkbdInternalState->keyboardArg.receiverArg.stringBufSize;
		if (stringBufferSize > 1)
		{
			maxLength = stringBufferSize - 1; // don't count the null-termination character
		}
		else
			maxLength = 0;
	}
	// In keyboard-only fixed-slot mode (fixedCharLimit >= 0, e.g. a PIN pad) the cursor
	// must always sit at the end of the string — characters append left-to-right with no
	// mid-string editing.  Guard on keyboardOnlyMode so that input-form mode is not
	// affected (fixedCharLimit may be 0 from memset when SetReceiver was never called).
	const bool fixedSlot = swkbdInternalState->keyboardOnlyMode &&
	                       (sint32)swkbdInternalState->keyboardArg.receiverArg.fixedCharLimit >= 0;
	// insert character at cursorPos (or at end when in fixed-slot mode)
	if (swkbdInternalState->formStringLength < maxLength)
	{
		const sint32 insertPos = fixedSlot ? swkbdInternalState->formStringLength : swkbdInternalState->cursorPos;
		// Shift everything from insertPos onward one position right to make room.
		for (sint32 i = swkbdInternalState->formStringLength; i > insertPos; i--)
			swkbdInternalState->formStringBuffer[i] = swkbdInternalState->formStringBuffer[i - 1];
		swkbdInternalState->formStringBuffer[insertPos] = keyCode;
		swkbdInternalState->formStringLength++;
		swkbdInternalState->cursorPos = insertPos + 1; // one past the inserted char
		// In fixed-slot mode insertPos == old formStringLength, so this equals new formStringLength (end). ✓
		// In free-cursor mode insertPos == old cursorPos, so this equals old cursorPos + 1. ✓
		swkbdInternalState->formStringBuffer[swkbdInternalState->formStringLength] = L'\0';
		// Dirty range: pure insertion at insertPos — nothing was removed from the old string.
		swkbd_inputStringChanged(insertPos, insertPos);
	}
}

namespace swkbd
{
	class : public COSModule
	{
		public:
		std::string_view GetName() override
		{
			return "swkbd";
		}

		void RPLMapped() override
		{
			osLib_addFunction("swkbd", "SwkbdCreate__3RplFPUcQ3_2nn5swkbd10RegionTypeUiP8FSClient", swkbdExport_SwkbdCreate);
			osLib_addFunction("swkbd", "SwkbdGetStateKeyboard__3RplFv", swkbdExport_SwkbdGetStateKeyboard);
			osLib_addFunction("swkbd", "SwkbdGetStateInputForm__3RplFv", swkbdExport_SwkbdGetStateInputForm);
			osLib_addFunction("swkbd", "SwkbdSetReceiver__3RplFRCQ3_2nn5swkbd11ReceiverArg", swkbdExport_SwkbdSetReceiver);
			osLib_addFunction("swkbd", "SwkbdAppearInputForm__3RplFRCQ3_2nn5swkbd9AppearArg", swkbdExport_SwkbdAppearInputForm);
			osLib_addFunction("swkbd", "SwkbdDisappearInputForm__3RplFv", swkbdExport_SwkbdDisappearInputForm);
			osLib_addFunction("swkbd", "SwkbdDisappearKeyboard__3RplFv", swkbdExport_SwkbdDisappearKeyboard);
			osLib_addFunction("swkbd", "SwkbdAppearKeyboard__3RplFRCQ3_2nn5swkbd11KeyboardArg", swkbdExport_SwkbdAppearKeyboard);
			osLib_addFunction("swkbd", "SwkbdGetInputFormString__3RplFv", swkbdExport_SwkbdGetInputFormString);
			osLib_addFunction("swkbd", "SwkbdIsDecideOkButton__3RplFPb", swkbdExport_SwkbdIsDecideOkButton);
			osLib_addFunction("swkbd", "SwkbdIsDecideCancelButton__3RplFPb", swkbdExport_SwkbdIsDecideCancelButton);
			osLib_addFunction("swkbd", "SwkbdSetEnableOkButton__3RplFb", swkbdExport_SwkbdSetEnableOkButton);
			osLib_addFunction("swkbd", "SwkbdInitLearnDic__3RplFPv", swkbdExport_SwkbdInitLearnDic);
			osLib_addFunction("swkbd", "SwkbdGetDrawStringInfo__3RplFPQ3_2nn5swkbd14DrawStringInfo", swkbdExport_SwkbdGetDrawStringInfo);
			osLib_addFunction("swkbd", "SwkbdIsNeedCalcSubThreadFont__3RplFv", swkbdExport_SwkbdIsNeedCalcSubThreadFont);
			osLib_addFunction("swkbd", "SwkbdIsNeedCalcSubThreadPredict__3RplFv", swkbdExport_SwkbdIsNeedCalcSubThreadPredict);
		};

		void rpl_entry(uint32 moduleHandle, coreinit::RplEntryReason reason) override
		{
			if (reason == coreinit::RplEntryReason::Loaded)
			{
				// todo
			}
			else if (reason == coreinit::RplEntryReason::Unloaded)
			{
				// todo
			}
		}
	}s_COSswkbdModule;

	COSModule* GetModule()
	{
		return &s_COSswkbdModule;
	}
}
