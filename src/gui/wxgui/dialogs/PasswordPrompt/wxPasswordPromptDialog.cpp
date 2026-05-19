#include "wxgui/dialogs/PasswordPrompt/wxPasswordPromptDialog.h"

#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <wx/checkbox.h>
#include <wx/button.h>
#include <wx/msgdlg.h>
#include <wx/settings.h>

wxPasswordPromptDialog::wxPasswordPromptDialog(wxWindow* parent, wxString miiName, wxString serviceName,
                                               bool showIncorrectPasswordError)
	: wxDialog(parent, wxID_ANY, _("Enter account password"))
{
	auto* main_sizer = new wxBoxSizer(wxVERTICAL);

	wxString description = wxString::Format(_("Please enter the password for %s"), miiName);
	auto* desc = new wxStaticText(this, wxID_ANY, description);
	desc->Wrap(420);
	main_sizer->Add(desc, 0, wxLEFT | wxRIGHT | wxTOP | wxEXPAND, 8);

	if (!serviceName.IsEmpty())
	{
		wxString connectingText = wxString::Format(_("Connecting to %s"), serviceName);
		auto* connecting = new wxStaticText(this, wxID_ANY, connectingText);
		wxFont font = connecting->GetFont();
		font.SetPointSize(std::max(6, font.GetPointSize() - 1));
		connecting->SetFont(font);
		connecting->SetForegroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_GRAYTEXT));
		main_sizer->Add(connecting, 0, wxLEFT | wxRIGHT | wxBOTTOM | wxEXPAND, 8);
	}
	else
	{
		main_sizer->AddSpacer(4);
	}

	// Inline themed error banner shown on a retry after a failed verification.
	// Replaces the previous native wxMessageBox so it respects the dark-mode
	// styling of the parent window.
	if (showIncorrectPasswordError)
	{
		auto* err = new wxStaticText(this, wxID_ANY, _("Incorrect password. Please try again."));
		wxFont errFont = err->GetFont();
		errFont.SetWeight(wxFONTWEIGHT_BOLD);
		err->SetFont(errFont);
		// Soft red that reads well on both light and dark backgrounds.
		err->SetForegroundColour(wxColour(220, 64, 64));
		main_sizer->Add(err, 0, wxLEFT | wxRIGHT | wxBOTTOM | wxEXPAND, 8);
	}

	auto* row = new wxFlexGridSizer(0, 3, 0, 0);
	row->AddGrowableCol(1);

	row->Add(new wxStaticText(this, wxID_ANY, _("Password")), 0, wxALIGN_CENTER_VERTICAL | wxALL, 5);
	m_password = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxSize(240, -1), wxTE_PASSWORD | wxTE_PROCESS_ENTER);
	m_password->SetMaxLength(16); // matches LoadConsoleAccount's 16-char cap
	m_password->SetFocus();
	m_password->Bind(wxEVT_TEXT_ENTER, &wxPasswordPromptDialog::OnOK, this);
	row->Add(m_password, 1, wxALL | wxEXPAND, 5);

	// "?" help button to the right of the password field. wxWidgets can't
	// portably add buttons to the OS title bar, so this is the most prominent
	// in-dialog placement adjacent to the field the prompt is about.
	m_help_button = new wxButton(this, wxID_ANY, "?", wxDefaultPosition, wxSize(28, 28));
	m_help_button->SetToolTip(_("Why am I seeing this prompt?"));
	m_help_button->Bind(wxEVT_BUTTON, &wxPasswordPromptDialog::OnShowHelp, this);
	row->Add(m_help_button, 0, wxALIGN_CENTER_VERTICAL | wxALL, 5);

	main_sizer->Add(row, 0, wxEXPAND);

	m_show_password = new wxCheckBox(this, wxID_ANY, _("Show password"));
	m_show_password->SetValue(false);
	m_show_password->Bind(wxEVT_CHECKBOX, &wxPasswordPromptDialog::OnToggleShowPassword, this);
	main_sizer->Add(m_show_password, 0, wxLEFT | wxRIGHT | wxTOP, 8);

	m_save_password = new wxCheckBox(this, wxID_ANY, _("Save password"));
	m_save_password->SetValue(false);
	main_sizer->Add(m_save_password, 0, wxALL, 8);

	auto* button_sizer = new wxBoxSizer(wxHORIZONTAL);

	// "Launch offline" sits on the left, visually separated from the primary
	// OK/Cancel pair on the right. This is the themed replacement for the
	// previous wxMessageBox "Launch in offline mode?" prompt.
	m_offline_button = new wxButton(this, wxID_ANY, _("Offline Mode"));
	m_offline_button->SetToolTip(_("skip account password and launch in offline mode"));
	m_offline_button->Bind(wxEVT_BUTTON, &wxPasswordPromptDialog::OnLaunchOffline, this);
	button_sizer->Add(m_offline_button, 0, wxALL, 5);

	button_sizer->AddStretchSpacer(1);

	m_ok_button = new wxButton(this, wxID_ANY, _("OK"));
	m_ok_button->Bind(wxEVT_BUTTON, &wxPasswordPromptDialog::OnOK, this);
	button_sizer->Add(m_ok_button, 0, wxALL, 5);

	m_cancel_button = new wxButton(this, wxID_ANY, _("Cancel"));
	m_cancel_button->Bind(wxEVT_BUTTON, &wxPasswordPromptDialog::OnCancel, this);
	button_sizer->Add(m_cancel_button, 0, wxALL, 5);

	main_sizer->Add(button_sizer, 0, wxEXPAND);

	this->SetSizerAndFit(main_sizer);
	this->wxWindowBase::Layout();
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

void wxPasswordPromptDialog::OnShowHelp(wxCommandEvent& event)
{
	// Themed wxDialog rather than a native wxMessageBox so the explanation
	// inherits the same dark-mode treatment as the rest of the password flow.
	wxDialog dlg(this, wxID_ANY, _("Why am I seeing this prompt?"));
	auto* sizer = new wxBoxSizer(wxVERTICAL);

	const wxString text = _(
		"This account hasn't saved the password. As a result you'll have to "
		"enter your password to access online features.\n\n"
		"After entering your password you'll have the option to save it via "
		"the check box, so you will not need to enter it again in the future.\n\n"
		"You'll have the ability to delete the password in the account "
		"settings in General Settings if you regret saving it.\n\n"
		"You can also just launch the account without the password by pressing "
		"the \"Offline Mode\" button, at the cost of not getting access to "
		"online features.");

	auto* body = new wxStaticText(&dlg, wxID_ANY, text);
	body->Wrap(440);
	sizer->Add(body, 1, wxALL | wxEXPAND, 12);

	auto* button_row = new wxBoxSizer(wxHORIZONTAL);
	button_row->AddStretchSpacer(1);
	auto* ok = new wxButton(&dlg, wxID_OK, _("OK"));
	ok->SetDefault();
	button_row->Add(ok, 0, wxALL, 6);
	sizer->Add(button_row, 0, wxEXPAND);

	dlg.SetSizerAndFit(sizer);
	dlg.CentreOnParent();
	dlg.ShowModal();
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
