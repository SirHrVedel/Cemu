#pragma once
#include <wx/dialog.h>
#include <wx/string.h>

// Modal dialog shown before launching a title when the active account is an
// online account but has IsPasswordCacheEnabled=0 in account.dat. The user
// types the NNID password (max 16 chars to match the LoadConsoleAccount limit)
// and optionally ticks the "Save password" checkbox to persist the hashed
// cache to account.dat. When the box is unchecked the password lives only in
// memory for this Cemu session.
//
// Return values from ShowModal():
//   wxID_OK             - password entered, caller should verify+apply it
//   wxID_CANCEL         - user dismissed the dialog, abort launch
//   ID_LaunchOffline    - user picked offline-mode-for-this-session
class wxPasswordPromptDialog : public wxDialog
{
public:
	// Custom return id for the "Launch offline" button.
	static constexpr int ID_LaunchOffline = wxID_HIGHEST + 4101;

	// `showIncorrectPasswordError` displays an inline red error banner under
	// the title text. The caller sets this to true on retries after a failed
	// VerifyPlaintextPassword() so the user sees themed feedback instead of a
	// native wxMessageBox.
	wxPasswordPromptDialog(wxWindow* parent, wxString miiName, wxString serviceName,
	                       bool showIncorrectPasswordError = false);

	[[nodiscard]] wxString GetPassword() const;
	[[nodiscard]] bool ShouldSavePassword() const;

private:
	class wxTextCtrl* m_password = nullptr;
	class wxCheckBox* m_show_password = nullptr;
	class wxCheckBox* m_save_password = nullptr;
	class wxButton* m_ok_button = nullptr;
	class wxButton* m_cancel_button = nullptr;
	class wxButton* m_offline_button = nullptr;
	class wxButton* m_help_button = nullptr;

	void OnOK(wxCommandEvent& event);
	void OnCancel(wxCommandEvent& event);
	void OnLaunchOffline(wxCommandEvent& event);
	// Recreates m_password with/without wxTE_PASSWORD when "Show password" is
	// toggled (the native style is fixed at widget creation on Windows).
	void OnToggleShowPassword(wxCommandEvent& event);
	// Shows a wxDialog-based info popup explaining why the prompt appeared
	// and what the Save / Offline Mode options do.
	void OnShowHelp(wxCommandEvent& event);
};
