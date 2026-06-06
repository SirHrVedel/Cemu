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
	// imgui keyboard drawing stuff
	bool shiftActivated;
	bool returnState;
	bool cancelState;
	
}swkbdInternalState_t;

swkbdInternalState_t* swkbdInternalState = NULL;

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

void swkbdExport_SwkbdGetStateKeyboard(PPCInterpreter_t* hCPU)
{
	uint32 r = SWKBD_STATE_BLANK;
	if( swkbdInternalState->isActive )
		r = SWKBD_STATE_DISPLAYED;
	osLib_returnFromFunction(hCPU, r);
}

void swkbdExport_SwkbdGetStateInputForm(PPCInterpreter_t* hCPU)
{
	//debug_printf("SwkbdGetStateInputForm__3RplFv LR: %08x\n", hCPU->sprNew.LR);
	uint32 r = SWKBD_STATE_BLANK;
	if( swkbdInternalState->isActive )
		r = SWKBD_STATE_DISPLAYED;
	osLib_returnFromFunction(hCPU, r);
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


typedef struct  
{
	MPTR vTable; // guessed
}swkdbIEventReceiver_t;

typedef struct  
{
	uint32 ukn00;
	uint32 ukn04;
	uint32 ukn08;
	MPTR   onDirtyString;
}swkdbIEventReceiverVTable_t;

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
	/* +0x00 */ uint32 ukn00;
	/* +0x04 */ uint32 ukn04;
	/* +0x08 */ uint32 ukn08;
	/* +0x0C */ uint32 ukn0C;
	/* +0x10 */ uint32 ukn10;
	/* +0x14 */ uint32 ukn14;
	/* +0x18 */ uint32 ukn18;
	/* +0x1C */ uint32 ukn1C; // pointer to OK string
	/* +0x20 */ uint32 ukn20[4];
	/* +0x30 */ uint32 ukn30[4];
	/* +0x40 */ uint32 ukn40[4];
	/* +0x50 */ uint32 ukn50[4];
	/* +0x60 */ uint32 ukn60[4];
	/* +0x70 */ uint32 ukn70[4];
	/* +0x80 */ uint32 ukn80[4];
	/* +0x90 */ uint32 ukn90[4];
	/* +0xA0 */ uint32 uknA0[4];
	/* +0xB0 */ uint32 uknB0[4];
	/* +0xC0 */ uint32 inputFormType;
	/* +0xC4 */ uint32be cursorIndex;
	/* +0xC8 */ MEMPTR<uint16be> initialText;
	/* +0xCC */ MEMPTR<uint16be> infoText;
	/* +0xD0 */ uint32be maxTextLength;

}swkbdAppearArg_t;

static_assert(offsetof(swkbdAppearArg_t, cursorIndex) == 0xC4, "appearArg.cursorIndex has invalid offset");

void swkbdExport_SwkbdAppearInputForm(PPCInterpreter_t* hCPU)
{
	ppcDefineParamStructPtr(appearArg, swkbdAppearArg_t, 0);
	cemuLog_logDebug(LogType::Force, "SwkbdAppearInputForm__3RplFRCQ3_2nn5swkbd9AppearArg");
	swkbdInternalState->formStringLength = 0;
	swkbdInternalState->infoTextBuffer[0] = L'\0';
	swkbdInternalState->isActive = true;
	swkbdInternalState->decideButtonWasPressed = false;
	swkbdInternalState->cancelButtonWasPressed = false;
	swkbdInternalState->keyboardOnlyMode = false;

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
	// Copy the optional info label (shown above the input field).
	{
		const uint16be* infoStr = appearArg->infoText.GetPtr();
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

	uint32 argPtr = hCPU->gpr[3];
	for(sint32 i=0; i<0x180; i += 4)
	{
		debug_printf("+0x%03x: 0x%08x\n", i, memory_readU32(argPtr+i));
	}

	swkbdInternalState->formStringLength = 0;
	swkbdInternalState->infoTextBuffer[0] = L'\0';
	swkbdInternalState->isActive = true;
	swkbdInternalState->keyboardOnlyMode = true;
	swkbdInternalState->decideButtonWasPressed = false;
	swkbdInternalState->cancelButtonWasPressed = false;
	swkbdInternalState->formStringBuffer[0] = '\0';
	swkbdInternalState->formStringLength = 0;
	swkbdInternalState->keyboardArg = *keyboardArg;
	osLib_returnFromFunction(hCPU, 1);
}

void swkbdExport_SwkbdDisappearInputForm(PPCInterpreter_t* hCPU)
{
	debug_printf("SwkbdDisappearInputForm__3RplFv LR: %08x\n", hCPU->spr.LR);
	swkbdInternalState->isActive = false;
	osLib_returnFromFunction(hCPU, 1);
}

void swkbdExport_SwkbdDisappearKeyboard(PPCInterpreter_t* hCPU)
{
	debug_printf("SwkbdDisappearKeyboard__3RplFv LR: %08x\n", hCPU->spr.LR);
	swkbdInternalState->isActive = false;
	osLib_returnFromFunction(hCPU, 1);
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
	if (swkbdInternalState->decideButtonWasPressed)
		osLib_returnFromFunction(hCPU, 1);
	else
		osLib_returnFromFunction(hCPU, 0);
}

void swkbdExport_SwkbdIsDecideCancelButton(PPCInterpreter_t* hCPU)
{
	if (swkbdInternalState->cancelButtonWasPressed)
		osLib_returnFromFunction(hCPU, 1);
	else
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

bool isNeedCalc0 = true;
bool isNeedCalc1 = true;

void swkbdExport_SwkbdIsNeedCalcSubThreadFont(PPCInterpreter_t* hCPU)
{
	// SwkbdIsNeedCalcSubThreadFont__3RplFv
	bool r = false;
	osLib_returnFromFunction(hCPU, r?1:0);
}

void swkbdExport_SwkbdIsNeedCalcSubThreadPredict(PPCInterpreter_t* hCPU)
{
	// SwkbdIsNeedCalcSubThreadPredict__3RplFv
	bool r = false;

	osLib_returnFromFunction(hCPU, r?1:0);
}

void swkbd_keyInput(uint32 keyCode);
void swkbd_render(bool mainWindow)
{
	// Animation state: separate timers for appear and disappear.
	// Shared statics so both the main window and GamePad window use the same timestamps.
	static std::chrono::steady_clock::time_point s_appear_time;
	static std::chrono::steady_clock::time_point s_disappear_time;
	static bool s_was_active   = false;
	static bool s_disappearing = false;

	const bool nowActive = (swkbdInternalState != NULL && swkbdInternalState->isActive);

	if (nowActive && !s_was_active)
	{
		// Keyboard just appeared — start fade-in, cancel any in-progress fade-out.
		s_appear_time  = tick_cached();
		s_disappearing = false;
	}
	else if (!nowActive && s_was_active)
	{
		// Keyboard just dismissed — start fade-out.
		s_disappear_time = tick_cached();
		s_disappearing   = true;
	}
	s_was_active = nowActive;

	constexpr float kAnimDuration = 0.25f;

	if (s_disappearing)
	{
		const float elapsed = std::chrono::duration<float>(tick_cached() - s_disappear_time).count();
		if (elapsed >= kAnimDuration)
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
	// The existing slide formula  40*(1-eased)  already reverses automatically:
	//   appearing   → offset 40→0  (slides up)
	//   disappearing → offset 0→40  (slides down)
	const float eased = [&]()
	{
		if (s_disappearing)
		{
			const float t = std::min(std::chrono::duration<float>(tick_cached() - s_disappear_time).count() / kAnimDuration, 1.0f);
			return (1.0f - t) * (1.0f - t); // fast exit, gentle finish
		}
		const float t = std::min(std::chrono::duration<float>(tick_cached() - s_appear_time).count() / kAnimDuration, 1.0f);
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
	//
	//   Target sizes at 720p (scale=1):
	//     keyboard buttons  36 px  kbdScale   = 36/64
	//     input field       52 px  inputScale = 52/64
	//     info label        40 px  infoScale  = 40/64
	constexpr float kBaseFontSz = 64.0f;
	const auto baseFont = ImGui_GetFont(kBaseFontSz);
	if (!baseFont)
		return; // font queued for loading; renders correctly next frame
	const float kbdScale   = (52.0f * scale) / kBaseFontSz;
	const float inputScale = (52.0f * scale) / kBaseFontSz;
	const float infoScale  = (52.0f * scale) / kBaseFontSz;

	// ── Layout metrics ────────────────────────────────────────────────────────
	const float kWinPadX  = ImGui::GetStyle().WindowPadding.x;
	const float kWinPadY  = ImGui::GetStyle().WindowPadding.y;
	const float kItemSpX  = ImGui::GetStyle().ItemSpacing.x;
	const float kItemSpY  = ImGui::GetStyle().ItemSpacing.y;
	const float kInnerW   = cW - kWinPadX * 2.0f;
	// 12 keys fill the full canvas width (widest row: digits + backspace).
	const float keyWidth   = (kInnerW - kItemSpX * 11.0f) / 12.0f;
	// Space bar fills what remains after back, shift, and enter on the bottom row.
	const float spaceWidth = kInnerW - keyWidth * 3.0f - kItemSpX * 3.0f;
	// Five rows + four gaps + top/bottom padding = exactly cH/2.
	const float keyHeight  = (cH * 0.5f - 4.0f * kItemSpY - 2.0f * kWinPadY) / 5.0f;
	// Slide animation offset scales with the canvas so it feels the same at every resolution.
	const float slideOffset = 40.0f * scale * (1.0f - eased);

	const auto kPopupFlags = ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings;

	// ── Global style pushes ───────────────────────────────────────────────────
	ImGui::PushStyleColor(ImGuiCol_WindowBg, 0);
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, eased);

	// Background dim — canvas only, never bleeds into letterbox borders.
	ImGui::SetNextWindowPos(canvasMin, ImGuiCond_Always);
	ImGui::SetNextWindowSize({ cW, cH }, ImGuiCond_Always);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, { 0,0 });
	ImGui::SetNextWindowBgAlpha(0.8f * eased);
	ImGui::Begin("Background overlay", nullptr, kPopupFlags | ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoBringToFrontOnFocus);
	ImGui::End();
	ImGui::PopStyleVar(2);

	// The info label and input box are treated as one visual group whose combined
	// height is centred on the middle of the upper half of the canvas.
	const float anchorY      = canvasMin.y + cH * 0.25f;
	const float fieldWidth   = cW * 0.8f;
	const float kFramePadY  = ImGui::GetStyle().FramePadding.y;
	// Estimated single-line height of the input box (font + padding).
	const float inputH      = 52.0f * scale + 2.0f * kWinPadY + 2.0f * kFramePadY;
	// Info text uses a bottom pivot so multi-line text grows upward, never
	// overlapping the input field below it.
	const float infoBottomY = anchorY - inputH * 0.5f - 6.0f * scale;

	// Info label — transparent, bottom-pivot, centre-aligned word-wrapped text.
	if (swkbdInternalState->infoTextBuffer[0] != L'\0')
	{
		 const auto infoStr = boost::nowide::narrow(fmt::format(L"{}", swkbdInternalState->infoTextBuffer));
    ImGui::SetNextWindowBgAlpha(0.0f);
    ImGui::SetNextWindowSizeConstraints({ fieldWidth, 0.0f }, { fieldWidth, FLT_MAX });
    ImGui::SetNextWindowPos({ canvasMin.x + cW * 0.5f, infoBottomY },
                            ImGuiCond_Always, { 0.5f, 1.0f });
    ImGui::PushFont(baseFont);
    if (ImGui::Begin("Keyboard Info Label", nullptr, kPopupFlags | ImGuiWindowFlags_NoBackground))
    {
      ImGui::SetWindowFontScale(infoScale);
      // SetCursorPosX is relative to the window left edge (not content region),
      // so use GetWindowWidth() as the container for the centering formula.
      // Wrap still guards against the content area (minus padding on both sides).
      const float windowW  = ImGui::GetWindowWidth();
      const float wrapW    = windowW - 2.0f * kWinPadX;
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

	// Input box — 80 % canvas width, centre pivot on anchorY.
	ImGui::SetNextWindowSizeConstraints({ fieldWidth, 0.0f }, { fieldWidth, FLT_MAX });
	ImGui::SetNextWindowPos({ canvasMin.x + cW * 0.5f, anchorY },
	                        ImGuiCond_Always, { 0.5f, 0.5f });
	ImGui::SetNextWindowBgAlpha(0.9f * eased);
	ImGui::PushFont(baseFont);
	if (ImGui::Begin("Keyboard Input", nullptr, kPopupFlags))
	{
		ImGui::SetWindowFontScale(inputScale);
		ImGui::Text("%s", _utf8WrapperPtr(ICON_FA_KEYBOARD));
		ImGui::SameLine(0, 8);
		auto text = boost::nowide::narrow(fmt::format(L"{}", swkbdInternalState->formStringBuffer));

		static std::chrono::steady_clock::time_point s_last_tick = tick_cached();
		static bool s_blink_state = false;
		const auto now = tick_cached();

		if (std::chrono::duration_cast<std::chrono::milliseconds>(now - s_last_tick).count() >= 500)
		{
			s_blink_state = !s_blink_state;
			s_last_tick = now;
		}

		if (s_blink_state)
			text += "|";

		ImGui::PushTextWrapPos();
		ImGui::TextUnformatted(text.c_str(), text.c_str() + text.size());
		ImGui::PopTextWrapPos();
	}
	ImGui::End();
	ImGui::PopFont();

	// Keyboard — bottom-centre pivot at canvas bottom; slides in/out via slideOffset.
	ImGui::SetNextWindowSizeConstraints({ cW, 0.0f }, { cW, FLT_MAX });
	ImGui::SetNextWindowPos({ canvasMin.x + cW * 0.5f, canvasMin.y + cH + slideOffset },
	                        ImGuiCond_Always, { 0.5f, 1.0f });
	ImGui::SetNextWindowBgAlpha(0.9f * eased);
	ImGui::PushFont(baseFont);

	if (ImGui::Begin(fmt::format("Software keyboard##SoftwareKeyboard{}",mainWindow).c_str(), nullptr, kPopupFlags))
	{
		ImGui::SetWindowFontScale(kbdScale);
		if(swkbdInternalState->shiftActivated)
		{
			const char* keys[] =
			{
				"#", "[", "]", "$", "%", "^", "&", "*", "(", ")", "_", _utf8WrapperPtr(ICON_FA_ARROW_CIRCLE_LEFT), "\n",
				"Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P", "@", "\n",
				"A", "S", "D", "F", "G", "H", "J", "K", "L", ";", "\"", "\n",
				"Z", "X", "C", "V", "B", "N", "M", "<", ">", "+", "=", "\n",
				_utf8WrapperPtr(ICON_FA_TIMES), _utf8WrapperPtr(ICON_FA_ARROW_UP), " ", _utf8WrapperPtr(ICON_FA_CHECK)
			};
			for (auto key : keys)
			{
				if (*key != '\n')
				{
					ImGui::Button(key, { *key == ' ' ? spaceWidth : keyWidth, keyHeight });
					if (ImGui::IsItemClicked())
					{
						if (strcmp(key, _utf8WrapperPtr(ICON_FA_TIMES)) == 0)
							swkbdInternalState->cancelButtonWasPressed = true; // mirrors OK: game polls SwkbdIsDecideCancelButton then calls SwkbdDisappearInputForm
						else if (strcmp(key, _utf8WrapperPtr(ICON_FA_ARROW_CIRCLE_LEFT)) == 0)
							swkbd_keyInput(8);
						else if (strcmp(key, _utf8WrapperPtr(ICON_FA_ARROW_UP)) == 0)
							swkbdInternalState->shiftActivated = !swkbdInternalState->shiftActivated;
						else if (strcmp(key, _utf8WrapperPtr(ICON_FA_CHECK)) == 0)
							swkbd_keyInput(13);
						else
							swkbd_keyInput(*key);
					}

					ImGui::SameLine();
				}
				else
					ImGui::NewLine();
			}
		}
		else
		{
			const char* keys[] =
			{
				"1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", _utf8WrapperPtr(ICON_FA_ARROW_CIRCLE_LEFT), "\n",
				"q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "/", "\n",
				"a", "s", "d", "f", "g", "h", "j", "k", "l", ":", "'", "\n",
				"z", "x", "c", "v", "b", "n", "m", ",", ".", "?", "!", "\n",
				_utf8WrapperPtr(ICON_FA_TIMES), _utf8WrapperPtr(ICON_FA_ARROW_UP), " ", _utf8WrapperPtr(ICON_FA_CHECK)
			};
			for (auto key : keys)
			{
				if (*key != '\n')
				{
					ImGui::Button(key, { *key == ' ' ? spaceWidth : keyWidth, keyHeight });
					if (ImGui::IsItemClicked())
					{
						if (strcmp(key, _utf8WrapperPtr(ICON_FA_TIMES)) == 0)
							swkbdInternalState->cancelButtonWasPressed = true; // mirrors OK: game polls SwkbdIsDecideCancelButton then calls SwkbdDisappearInputForm
						else if (strcmp(key, _utf8WrapperPtr(ICON_FA_ARROW_CIRCLE_LEFT)) == 0)
							swkbd_keyInput(8);
						else if (strcmp(key, _utf8WrapperPtr(ICON_FA_ARROW_UP)) == 0)
							swkbdInternalState->shiftActivated = !swkbdInternalState->shiftActivated;
						else if (strcmp(key, _utf8WrapperPtr(ICON_FA_CHECK)) == 0)
							swkbd_keyInput(13);
						else
							swkbd_keyInput(*key);
					}

					ImGui::SameLine();
				}
				else
					ImGui::NewLine();
			}
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
		if (io.NavInputs[ImGuiNavInput_Cancel] > 0)
		{
			if (!swkbdInternalState->cancelState)
				swkbd_keyInput(8); // backspace
			swkbdInternalState->cancelState = true;
		}
		else
			swkbdInternalState->cancelState = false;

		if (io.NavInputs[ImGuiNavInput_Input] > 0)
		{
			if (!swkbdInternalState->returnState)
				swkbd_keyInput(13); // return
			swkbdInternalState->returnState = true;
		}
		else
			swkbdInternalState->returnState = false;
	}

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
	swkbdInternalState->decideButtonWasPressed = true; // currently we always accept the input
}

typedef struct  
{
	uint32be beginIndex;
	uint32be endIndex;
}changeStringParam_t;

SysAllocator<changeStringParam_t> _changeStringParam;

void swkbd_inputStringChanged()
{
	if( true )//swkbdInternalState->keyboardOnlyMode )
	{
		// write changed string to application's string buffer
		uint32 stringBufferSize = swkbdInternalState->keyboardArg.receiverArg.stringBufSize; // in 2-byte words
		if( stringBufferSize > 1 )
		{
			stringBufferSize--; // don't count the null-termination character
			const auto stringBufferBE = swkbdInternalState->keyboardArg.receiverArg.stringBuf.GetPtr();
			sint32 copyLength = std::min((sint32)stringBufferSize, swkbdInternalState->formStringLength);
			for(sint32 i=0; i<copyLength; i++)
			{
				stringBufferBE[i] = swkbdInternalState->formStringBuffer[i];
			}
			stringBufferBE[copyLength] = '\0';

			//swkbdInternalState->keyboardArg.cursorPos = copyLength;
		}
		// IEventReceiver callback
		if (swkbdInternalState->keyboardArg.receiverArg.IEventReceiver)
		{
			SwkbdIEventReceiver_t* eventReceiver = swkbdInternalState->keyboardArg.receiverArg.IEventReceiver.GetPtr();
			MPTR cbChangeString = eventReceiver->vTable->changeString.GetMPTR();
			if (cbChangeString)
			{
				changeStringParam_t* changeStringParam = _changeStringParam.GetPtr();
				changeStringParam->beginIndex = 0;
				changeStringParam->endIndex = 0;
				coreinitAsyncCallback_add(cbChangeString, 2, memory_getVirtualOffsetFromPointer(eventReceiver), _changeStringParam.GetMPTR());
			}
		}
	}
}

void swkbd_keyInput(uint32 keyCode)
{
	if (keyCode == 8 || keyCode == 127) // backspace || backwards delete
	{
		if (swkbdInternalState->formStringLength > 0)
			swkbdInternalState->formStringLength--;
		swkbdInternalState->formStringBuffer[swkbdInternalState->formStringLength] = '\0';
		swkbd_inputStringChanged();
		return;
	}
	else if (keyCode == 13) // return
	{
		swkbd_finishInput();
		return;
	}
	// check if allowed character
	if ((keyCode >= 'a' && keyCode <= 'z') ||
		(keyCode >= 'A' && keyCode <= 'Z'))
	{
		// allowed
	}
	else if ((keyCode >= '0' && keyCode <= '9'))
	{
		// allowed
	}
	else if (keyCode == ' ' || keyCode == '.' || keyCode == '/' || keyCode == '?' || keyCode == '=')
	{
		// allowed
	}
	else if (keyCode < 32)
	{
		// control key
		return;
	}
	else
		;// return;
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
	// append character
	if (swkbdInternalState->formStringLength < maxLength)
	{
		swkbdInternalState->formStringBuffer[swkbdInternalState->formStringLength] = keyCode;
		swkbdInternalState->formStringLength++;
		swkbdInternalState->formStringBuffer[swkbdInternalState->formStringLength] = '\0';
		swkbd_inputStringChanged();
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
