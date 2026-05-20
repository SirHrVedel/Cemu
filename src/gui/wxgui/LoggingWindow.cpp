#include "wxgui/LoggingWindow.h"

#include "Cemu/Logging/CemuLogging.h"
#include "wxgui/helpers/wxLogEvent.h"

#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/wupdlock.h>

wxDEFINE_EVENT(EVT_LOG, wxLogEvent);

LoggingWindow::LoggingWindow(wxFrame* parent)
	: wxFrame(parent, wxID_ANY, _("Logging window"), wxDefaultPosition, wxSize(800, 600), wxDEFAULT_FRAME_STYLE | wxTAB_TRAVERSAL)
{
	auto* sizer = new wxBoxSizer( wxVERTICAL );
	{
		auto filter_row = new wxBoxSizer( wxHORIZONTAL );

		filter_row->Add(new wxStaticText( this, wxID_ANY, _("Filter")), 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );

		wxString choices[] = {"Unsupported APIs calls", "Coreinit Logging", "Coreinit File-Access", "Coreinit Thread-Synchronization", "Coreinit Memory", "Coreinit MP", "Coreinit Thread", "nn::nfp", "GX2", "Audio", "Input", "Socket", "Save", "H264", "Graphic pack patches", "Texture cache", "Texture readback", "OpenGL debug output", "Vulkan validation layer", "Metal debug output"};
		m_filter = new wxComboBox(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, std::size(choices), choices);
		m_filter->Bind(wxEVT_COMBOBOX, &LoggingWindow::OnFilterChange, this);
		m_filter->Bind(wxEVT_TEXT, &LoggingWindow::OnFilterChange, this);
		filter_row->Add(m_filter, 1, wxALL, 5 );

		m_filter_message = new wxCheckBox(this, wxID_ANY, _("Filter messages"));
		m_filter_message->Bind(wxEVT_CHECKBOX, &LoggingWindow::OnFilterMessageChange, this);
		filter_row->Add(m_filter_message, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );

		sizer->Add( filter_row, 0, wxEXPAND, 5 );
	}

	m_log_list = new wxLogCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxScrolledWindowStyle, true);
	sizer->Add( m_log_list, 1, wxALL | wxEXPAND, 5 );

	this->SetSizer( sizer );
	this->Layout();

	this->Bind(EVT_LOG, &LoggingWindow::OnLogMessage, this);

	cemuLog_setCallbacks(this);
}

LoggingWindow::~LoggingWindow()
{
	this->Unbind(EVT_LOG, &LoggingWindow::OnLogMessage, this);

	cemuLog_clearCallbacks();
}

void LoggingWindow::Log(std::string_view filter, std::string_view message)
{
	// cemuLog_log passes UTF-8 byte strings (CODING_STYLE.md), but wxString's
	// implicit ctor from std::string uses the platform's locale narrow
	// encoding (CP1252 on most Windows installs) and mangles non-ASCII bytes.
	// Use FromUTF8 explicitly so characters like aeoeo / e+ring / o-slash
	// (and any other multi-byte UTF-8) survive the trip into wxString.
	wxLogEvent event(wxString::FromUTF8(filter.data(), filter.size()),
	                 wxString::FromUTF8(message.data(), message.size()));
	OnLogMessage(event);
}

void LoggingWindow::Log(std::string_view filter, std::wstring_view message)
{
	wxLogEvent event(wxString::FromUTF8(filter.data(), filter.size()),
	                 wxString(message.data(), message.size()));
	OnLogMessage(event);
}

void LoggingWindow::OnLogMessage(wxLogEvent& event)
{
	m_log_list->PushEntry(event.GetFilter(), event.GetMessage());
}

void LoggingWindow::OnFilterChange(wxCommandEvent& event)
{
	m_log_list->SetActiveFilter(m_filter->GetValue().utf8_string());
	event.Skip();
}

void LoggingWindow::OnFilterMessageChange(wxCommandEvent& event)
{
	m_log_list->SetFilterMessage(m_filter_message->GetValue());
	event.Skip();
}
