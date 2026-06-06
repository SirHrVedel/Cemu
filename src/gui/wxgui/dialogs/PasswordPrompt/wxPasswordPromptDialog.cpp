#include "wxgui/dialogs/PasswordPrompt/wxPasswordPromptDialog.h"
#include "wxgui/helpers/wxHelpers.h"

#include <wx/panel.h>
#include <wx/sizer.h>
#include <wx/statline.h>
#include <wx/statbmp.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <wx/checkbox.h>
#include <wx/button.h>
#include <wx/msgdlg.h>
#include <wx/settings.h>


wxPasswordPromptDialog::wxPasswordPromptDialog(wxWindow* parent, wxString miiName, wxString serviceName,
                                               wxColour serviceColour, std::function<bool(const std::string&)> verifier,
                                               uint32 persistentId)
	: wxDialog(parent, wxID_ANY, _("Enter account password"))
	, m_verifier(std::move(verifier))
{
	const wxBitmap miiIcon = wxLoadMiiImage(persistentId);
	auto* main_sizer = new wxBoxSizer(wxVERTICAL);

	// Top row: description and password field on the left; Mii icon on the right.
	// The stretch spacer pushes the password field to the bottom of the Mii image
	// so the two are vertically aligned.
	auto* top_row = new wxBoxSizer(wxHORIZONTAL);
	auto* text_col = new wxBoxSizer(wxVERTICAL);

	const int wrapWidth = 280; // icon area is always shown
	auto* desc = new wxStaticText(this, wxID_ANY,
		wxString::Format(_("Please enter the password for %s"), miiName));
	desc->Wrap(wrapWidth);
	text_col->Add(desc, 0, wxLEFT | wxRIGHT | wxTOP | wxEXPAND, 8);

	// Fills the gap between the text above and the password field below so
	// the field sits at the bottom of the Mii image.
	text_col->AddStretchSpacer(1);

	auto* pw_row = new wxBoxSizer(wxHORIZONTAL);
	pw_row->Add(new wxStaticText(this, wxID_ANY, _("Password")), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
	m_password = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD | wxTE_PROCESS_ENTER);
	m_password->SetMaxLength(16); // matches LoadConsoleAccount's 16-char cap
	m_password->SetFocus();
	m_password->Bind(wxEVT_TEXT_ENTER, &wxPasswordPromptDialog::OnOK, this);
	pw_row->Add(m_password, 1, wxEXPAND);
	text_col->Add(pw_row, 0, wxALL | wxEXPAND, 8);

	top_row->Add(text_col, 1, wxEXPAND);

	// Outer panel provides the border ring; inner panel matches the dialog
	// background so transparent Mii pixels don't show the border colour.
	// Vertically centred so the row height is driven purely by content, not
	// by pushing the icon to the bottom of an artificially tall column.
	{
		auto* borderPanel = new wxPanel(this, wxID_ANY);
		borderPanel->SetBackgroundColour(wxColour(140, 140, 140));
		auto* borderSizer = new wxBoxSizer(wxHORIZONTAL);
		auto* bgPanel = new wxPanel(borderPanel, wxID_ANY);
		bgPanel->SetBackgroundColour(GetBackgroundColour());
		auto* bgSizer = new wxBoxSizer(wxHORIZONTAL);
		bgSizer->Add(new wxStaticBitmap(bgPanel, wxID_ANY, miiIcon), 0);
		bgPanel->SetSizer(bgSizer);
		bgPanel->Fit();
		borderSizer->Add(bgPanel, 0, wxALL, 1);
		borderPanel->SetSizer(borderSizer);
		borderPanel->Fit();
		top_row->Add(borderPanel, 0, wxALL | wxALIGN_BOTTOM, 6);
	}

	main_sizer->Add(top_row, 0, wxEXPAND);

	// Checkboxes on the left; "Connecting to …" fills the empty space on the right.
	auto* middle_row = new wxBoxSizer(wxHORIZONTAL);
	auto* checks_col = new wxBoxSizer(wxVERTICAL);

	m_show_password = new wxCheckBox(this, wxID_ANY, _("Show password"));
	m_show_password->SetValue(false);
	m_show_password->Bind(wxEVT_CHECKBOX, &wxPasswordPromptDialog::OnToggleShowPassword, this);
	checks_col->Add(m_show_password, 0, wxLEFT | wxRIGHT | wxTOP, 8);
	checks_col->AddSpacer(4); // equal outer margins → geometric centre = visual midpoint

	m_save_password = new wxCheckBox(this, wxID_ANY, _("Save password"));
	m_save_password->SetValue(false);
	checks_col->Add(m_save_password, 0, wxLEFT | wxRIGHT | wxBOTTOM, 8);

	middle_row->Add(checks_col, 0);

	if (!serviceName.IsEmpty())
	{
		// Two labels side-by-side: the static prefix stays grey, only the
		// service name adopts the network-specific colour.
		wxFont smallFont = GetFont();
		smallFont.SetPointSize(std::max(6, smallFont.GetPointSize() - 1));

		auto* service_sizer = new wxBoxSizer(wxHORIZONTAL);

		auto* prefix = new wxStaticText(this, wxID_ANY, _("Connecting to "));
		prefix->SetFont(smallFont);
		prefix->SetForegroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_GRAYTEXT));
		service_sizer->Add(prefix, 0, wxALIGN_CENTER_VERTICAL);

		auto* name = new wxStaticText(this, wxID_ANY, serviceName);
		name->SetFont(smallFont);
		name->SetForegroundColour(
			serviceColour.IsOk() ? serviceColour : wxSystemSettings::GetColour(wxSYS_COLOUR_GRAYTEXT));
		service_sizer->Add(name, 0, wxALIGN_CENTER_VERTICAL);

		middle_row->Add(service_sizer, 1, wxALIGN_CENTER_VERTICAL | wxALL, 8);
	}

	main_sizer->Add(middle_row, 0, wxEXPAND);

	auto* button_sizer = new wxBoxSizer(wxHORIZONTAL);

	// "Launch offline" sits on the left, visually separated from the primary
	// OK/Cancel pair on the right. This is the themed replacement for the
	// previous wxMessageBox "Launch in offline mode?" prompt.
	m_offline_button = new wxButton(this, wxID_ANY, _("Offline Mode"));
	m_offline_button->SetToolTip(_("Skip account password and temporarily launch in offline mode"));
	m_offline_button->Bind(wxEVT_BUTTON, &wxPasswordPromptDialog::OnLaunchOffline, this);
	button_sizer->Add(m_offline_button, 0, wxALL, 5);

	button_sizer->AddStretchSpacer(1);

	m_ok_button = new wxButton(this, wxID_ANY, _("OK"));
	m_ok_button->Bind(wxEVT_BUTTON, &wxPasswordPromptDialog::OnOK, this);
	button_sizer->Add(m_ok_button, 0, wxALL, 5);

	m_cancel_button = new wxButton(this, wxID_ANY, _("Cancel"));
	m_cancel_button->Bind(wxEVT_BUTTON, &wxPasswordPromptDialog::OnCancel, this);
	button_sizer->Add(m_cancel_button, 0, wxALL, 5);

	main_sizer->Add(new wxStaticLine(this), 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 8);
	main_sizer->Add(button_sizer, 0, wxEXPAND | wxALL, 4);

	this->SetSizerAndFit(main_sizer);
	this->wxWindowBase::Layout();
	CentreOnParent();
}

wxString wxPasswordPromptDialog::GetPassword() const
{
	return m_password ? m_password->GetValue() : wxString{};
}

bool wxPasswordPromptDialog::ShouldSavePassword() const
{
	return m_save_password && m_save_password->IsChecked();
}

void wxPasswordPromptDialog::OnOK(wxCommandEvent& event)
{
	if (m_password->IsEmpty())
		return; // require some input before accepting; field already focused

	if (m_verifier)
	{
		const std::string plaintext = m_password->GetValue().utf8_string();
		if (!m_verifier(plaintext))
		{
			wxMessageBox(_("Incorrect password. Please try again."),
			             _("Incorrect password"), wxOK | wxICON_ERROR, this);
			return; // keep dialog open; typed text is preserved
		}
	}

	EndModal(wxID_OK);
}

void wxPasswordPromptDialog::OnCancel(wxCommandEvent& event)
{
	EndModal(wxID_CANCEL);
}

void wxPasswordPromptDialog::OnLaunchOffline(wxCommandEvent& event)
{
	EndModal(ID_LaunchOffline);
}



void wxPasswordPromptDialog::OnToggleShowPassword(wxCommandEvent& event)
{
	// On Windows the EDIT control's password style is locked at creation, so
	// to toggle the masking we destroy the old wxTextCtrl and create a new
	// one with the flipped style, preserving the current value, size, and
	// position in the parent sizer.
	if (!m_password)
		return;
	const bool reveal = m_show_password && m_show_password->IsChecked();
	const wxString currentValue = m_password->GetValue();
	const wxSize currentSize = m_password->GetSize();
	long style = m_password->GetWindowStyleFlag();
	if (reveal)
		style &= ~wxTE_PASSWORD;
	else
		style |= wxTE_PASSWORD;

	wxSizer* containing = m_password->GetContainingSizer();
	if (!containing)
		return;

	auto* replacement = new wxTextCtrl(this, wxID_ANY, currentValue, wxDefaultPosition, currentSize, style);
	replacement->SetMaxLength(16);
	replacement->Bind(wxEVT_TEXT_ENTER, &wxPasswordPromptDialog::OnOK, this);

	containing->Replace(m_password, replacement);
	m_password->Destroy();
	m_password = replacement;
	m_password->SetFocus();
	m_password->SetInsertionPointEnd();
	Layout();
}
