#include "wxgui/helpers/wxHelpers.h"

#include <wx/image.h>
#include <wx/dcmemory.h>
#include <wx/settings.h>
#include <wx/wupdlock.h>
#include <wx/stattext.h>
#include <wx/slider.h>
#include <wx/dirdlg.h>

#include "config/ActiveSettings.h"
#include "util/helpers/helpers.h"

#if BOOST_OS_LINUX || BOOST_OS_BSD
#include <gtk/gtk.h>
#include <gdk/gdk.h>
#include <gdk/gdkwindow.h>
#include <gdk/gdkx.h>
#ifdef HAS_WAYLAND
#include <gdk/gdkwayland.h>
#endif
#endif

#include "wxgui/helpers/wxControlObject.h"

void wxAutosizeColumn(wxListCtrlBase* ctrl, int col)
{
	ctrl->SetColumnWidth(col, wxLIST_AUTOSIZE_USEHEADER);
	int wh = ctrl->GetColumnWidth(col);
	ctrl->SetColumnWidth(col, wxLIST_AUTOSIZE);
	int wc = ctrl->GetColumnWidth(col);
	if (wh > wc)
	ctrl->SetColumnWidth(col, wxLIST_AUTOSIZE_USEHEADER);
}

void wxAutosizeColumns(wxListCtrlBase* ctrl, int col_start, int col_end)
{
	wxWindowUpdateLocker lock(ctrl);
	for (int i = col_start; i <= col_end; ++i)
		wxAutosizeColumn(ctrl, i);
}

void update_slider_text(wxCommandEvent& event, const wxFormatString& format /*= "%d%%"*/)
{
	const auto slider = dynamic_cast<wxSlider*>(event.GetEventObject());
	wxASSERT(slider);

	auto slider_text = dynamic_cast<wxControlObject*>(event.GetEventUserData())->GetControl<wxStaticText>();
	wxASSERT(slider_text);

	slider_text->SetLabel(wxString::Format(format, slider->GetValue()));
}

uint32 fix_raw_keycode(uint32 keycode, uint32 raw_flags)
{
#if BOOST_OS_WINDOWS
	const auto flags = (HIWORD(raw_flags) & 0xFFF);
	if(keycode == VK_SHIFT)
	{
		if(flags == 0x2A)
			return 160;
		else if (flags == 0x36)
			return 161;
	}
	else if (keycode == VK_CONTROL)
	{
		if (flags == 0x1d)
			return 162;
		else if (flags == 0x11d)
			return 163;
	}
	else if (keycode == VK_MENU)
	{
		if ((flags & 0xFF) == 0x38)
			return 164;
		else if ((flags & 0xFF) == 0x38)
			return 165;
	}
#endif

	return keycode;
}

// Returns a `size x size` bitmap with a centred "?" drawn in the system grey-
// text colour on the dialog background. Used as the fallback when no Mii image
// is available so callers always receive a valid, correctly-sized bitmap.
static wxBitmap wxMakeMiiPlaceholder(int size)
{
	wxBitmap bmp(size, size);
	wxMemoryDC dc(bmp);
	dc.SetBackground(wxBrush(wxSystemSettings::GetColour(wxSYS_COLOUR_BTNFACE)));
	dc.Clear();
	wxFont font = dc.GetFont();
	font.SetPointSize(std::max(8, size * 7 / 16)); // ~28 pt at the default 64 px
	font.SetWeight(wxFONTWEIGHT_BOLD);
	dc.SetFont(font);
	dc.SetTextForeground(wxSystemSettings::GetColour(wxSYS_COLOUR_GRAYTEXT));
	const wxString label = wxT("?");
	wxCoord tw, th;
	dc.GetTextExtent(label, &tw, &th);
	dc.DrawText(label, (size - tw) / 2, (size - th) / 2);
	return bmp;
}

wxBitmap wxLoadMiiImage(uint32 persistentId, int size)
{
	const fs::path imgPath = ActiveSettings::GetMlcPath(
		fmt::format("usr/save/system/act/{:08x}/miiimg00.dat", persistentId));
	std::error_code ec;
	if (!fs::exists(imgPath, ec) || ec)
		return wxMakeMiiPlaceholder(size);
	wxImage img;
	if (!img.LoadFile(wxString::FromUTF8(_pathToUtf8(imgPath))))
		return wxMakeMiiPlaceholder(size);
	img.Rescale(size, size, wxIMAGE_QUALITY_HIGH);
	return wxBitmap(img);
}

WindowSystem::WindowHandleInfo initHandleContextFromWxWidgetsWindow(wxWindow* wxw)
{
	WindowSystem::WindowHandleInfo handleInfo;
#if BOOST_OS_WINDOWS
	handleInfo.backend = WindowSystem::WindowHandleInfo::Backend::Windows;
	handleInfo.surface = reinterpret_cast<void*>(wxw->GetHWND());
#elif BOOST_OS_LINUX || BOOST_OS_BSD
	GtkWidget* gtkWidget = (GtkWidget*)wxw->GetHandle(); // returns GtkWidget
	gtk_widget_realize(gtkWidget);
	GdkWindow* gdkWindow = gtk_widget_get_window(gtkWidget);
	GdkDisplay* gdkDisplay = gdk_window_get_display(gdkWindow);
	if (GDK_IS_X11_WINDOW(gdkWindow))
	{
		handleInfo.backend = WindowSystem::WindowHandleInfo::Backend::X11;
		handleInfo.surface = reinterpret_cast<void*>(gdk_x11_window_get_xid(gdkWindow));
		handleInfo.display = gdk_x11_display_get_xdisplay(gdkDisplay);
		if (!handleInfo.display)
		{
			cemuLog_log(LogType::Force, "Unable to get xlib display");
		}
	}
#ifdef HAS_WAYLAND
	else if (GDK_IS_WAYLAND_WINDOW(gdkWindow))
	{
		handleInfo.backend = WindowSystem::WindowHandleInfo::Backend::Wayland;
		handleInfo.surface = gdk_wayland_window_get_wl_surface(gdkWindow);
		handleInfo.display = gdk_wayland_display_get_wl_display(gdkDisplay);
	}
#endif
	else
	{
		cemuLog_log(LogType::Force, "Unsuported GTK backend");
	}
#elif BOOST_OS_MACOS
	handleInfo.backend = WindowSystem::WindowHandleInfo::Backend::Cocoa;
	handleInfo.surface = reinterpret_cast<void*>(wxw->GetHandle());
#endif
	return handleInfo;
}
