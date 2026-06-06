#pragma once
#include <functional>
#include <string>
#include <wx/dialog.h>
#include <wx/string.h>
#include <wx/colour.h>

// Modal dialog shown before launching a title when the active account is an
// online account with no usable cached password. The user types the NNID
// password (max 16 chars to match the LoadConsoleAccount limit) and optionally
// ticks the "Save password" checkbox to persist the hashed cache to
// account.dat. When the box is unchecked the password lives only in memory for
// this Cemu session. The `miiName` argument is shown verbatim in the prompt
// description, so callers may append the persistent id as "(xxxxxxxx)".
//
// If `verifier` is supplied, OnOK calls it with the plaintext before closing.
// On failure a wxMessageBox is shown and the dialog stays open with the typed
// text preserved. Pass nullptr to skip verification (caller handles it).
//
// Return values from ShowModal():
//   wxID_OK             - password entered and verified (or verifier is null)
//   wxID_CANCEL         - user dismissed the dialog, abort launch
//   ID_LaunchOffline    - user picked offline-mode-for-this-session
class wxPasswordPromptDialog : public wxDialog
{
public:
	// Custom return id for the "Launch offline" button.
	static constexpr int ID_LaunchOffline = wxID_HIGHEST + 4101;

	// `serviceColour` tints the "Connecting to …" label; pass wxNullColour to
	// use the default grey system text colour (e.g. when service is unknown).
	wxPasswordPromptDialog(wxWindow* parent, wxString miiName, wxString serviceName,
	                       wxColour serviceColour = wxNullColour,
	                       std::function<bool(const std::string&)> verifier = nullptr,
	                       uint32 persistentId = 0);

	[[nodiscard]] wxString GetPassword() const;
	[[nodiscard]] bool ShouldSavePassword() const;

private:
	std::function<bool(const std::string&)> m_verifier;
	class wxTextCtrl* m_password = nullptr;
	class wxCheckBox* m_show_password = nullptr;
	class wxCheckBox* m_save_password = nullptr;
	class wxButton* m_ok_button = nullptr;
	class wxButton* m_cancel_button = nullptr;
	class wxButton* m_offline_button = nullptr;

	void OnOK(wxCommandEvent& event);
	void OnCancel(wxCommandEvent& event);
	void OnLaunchOffline(wxCommandEvent& event);
	// Recreates m_password with/without wxTE_PASSWORD when "Show password" is
	// toggled (the native style is fixed at widget creation on Windows).
	void OnToggleShowPassword(wxCommandEvent& event);
};
