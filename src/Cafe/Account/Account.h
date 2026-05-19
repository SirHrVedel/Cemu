#pragma once

#include <string>
#include <string_view>
#include <system_error>

enum class OnlineAccountError
{
	kNone,
	kNoAccountId,
	kNoPasswordCached,
	kPasswordCacheEmpty,
	kNoPrincipalId,
};

struct OnlineValidator
{
	enum class FileState
	{
		Missing,
		Corrupted,
		Ok,
	};

	bool valid_account = false;
	FileState otp = FileState::Missing;
	FileState seeprom = FileState::Missing;
	std::vector<std::wstring> missing_files;
	OnlineAccountError account_error = OnlineAccountError::kNone;

	bool IsValid() const
	{
		return valid_account && otp == FileState::Ok && seeprom == FileState::Ok && missing_files.empty();
	}

	explicit operator bool() const
	{
		return IsValid();
	}
};

// Hashes a plaintext NNID password into the 32-byte AccountPasswordCache form
// stored in account.dat. Used by IOSU when LoadConsoleAccount supplies a
// password for an account that has password caching disabled.
void makePWHash(uint8* input, sint32 length, uint32 magic, uint8* output);

class Account
{
public:
	static constexpr uint32 kMinPersistendId = 0x80000001;
	
	// create dummy account object from scratch
	Account(uint32 persistent_id, std::wstring_view mii_name);

	// load an existing account
	Account(std::wstring_view file_name);

	std::error_code Load();
	std::error_code Save();

	[[nodiscard]] std::wstring ToString() const { return fmt::format(L"{} ({:x})", GetMiiName(), GetPersistentId()); }

	// test if the account file has all fields set required for online play
	[[nodiscard]] bool IsValidOnlineAccount() const;
	[[nodiscard]] OnlineAccountError GetOnlineAccountError() const;
	[[nodiscard]] fs::path GetFileName() const;

	[[nodiscard]] uint32 GetPersistentId() const { return m_persistent_id; }
	[[nodiscard]] uint64 GetTransferableIdBase() const { return m_transferable_id_base; }
	[[nodiscard]] const std::array<uint8, 16>& GetUuid() const { return m_uuid; }
	[[nodiscard]] const std::array<uint8, 96>& GetMiiData() const { return m_mii_data; }
	[[nodiscard]] std::wstring_view GetMiiName() const; // only max 10 characters excluding '\0'
	[[nodiscard]] std::string_view GetAccountId() const { return m_account_id; }
	[[nodiscard]] uint16 GetBirthYear() const { return m_birth_year; }
	[[nodiscard]] uint8 GetBirthMonth() const { return m_birth_month; }
	[[nodiscard]] uint8 GetBirthDay() const { return m_birth_day; }
	[[nodiscard]] uint8 GetGender() const { return m_gender; }
	[[nodiscard]] std::string_view GetEmail() const { return m_email; }
	[[nodiscard]] uint32 GetCountry() const { return m_country; }
	[[nodiscard]] uint32 GetSimpleAddressId() const { return m_simple_address_id; }
	[[nodiscard]] std::string_view GetTimeZoneId() const { return m_timezone_id; }
	[[nodiscard]] sint64 GetUtcOffset() const { return m_utc_offset; }
	[[nodiscard]] uint32 GetPrincipalId() const { return m_principal_id; }
	[[nodiscard]] bool IsPasswordCacheEnabled() const { return m_password_cache_enabled != 0; }
	[[nodiscard]] const std::array<uint8, 32>& GetAccountPasswordCache() const { return m_account_password_cache; }
	// True when the in-memory password cache was filled by the launch-time
	// prompt without "Save password" ticked. Survives only for this Cemu run.
	[[nodiscard]] bool HasSessionPassword() const { return m_session_password_filled; }
	// True when nn::act / NAPI have a usable password to send (either the
	// on-disk cache or a session-supplied one). Used by FileLoad to decide
	// whether to prompt. Distinct from IsPasswordCacheEnabled(), which must
	// continue to report the on-disk truth so the system menu's user-select
	// screen prompts correctly.
	[[nodiscard]] bool HasUsablePasswordForLaunch() const { return m_password_cache_enabled != 0 || m_session_password_filled; }

	[[nodiscard]] std::string_view GetStorageValue(std::string_view key) const;

	void SetMiiName(std::wstring_view name);
	void SetBirthYear(uint16 birth_year) { m_birth_year = birth_year; }
	void SetBirthMonth(uint8 birth_month) { m_birth_month = birth_month; }
	void SetBirthDay(uint8 birth_day) { m_birth_day = birth_day; }
	void SetGender(uint8 gender) { m_gender = gender; }
	void SetEmail(std::string_view email) { m_email = email; }
	void SetCountry(uint32 country) { m_country = country; }
	void SetTimeZoneId(std::string_view timezone_id) { m_timezone_id = timezone_id; }
	void SetUtcOffset(sint64 utc_offset) { m_utc_offset = utc_offset; }

	// Stores `plaintext` into m_account_password_cache after hashing it with
	// the principal-id-keyed makePWHash. Sets IsPasswordCacheEnabled=1 so the
	// rest of Cemu treats the slot as having a cached password. If `persist`
	// is true the account.dat is rewritten too; otherwise the change is
	// in-memory only for this Cemu session.
	void SetPasswordFromPlaintext(std::string_view plaintext, bool persist);
	void SetPasswordCacheEnabled(bool enabled) { m_password_cache_enabled = enabled ? 1 : 0; }

	// Returns true if the plaintext password hashes (double makePWHash) to
	// the AccountPasswordHash stored in account.dat. When the account has no
	// stored hash (or it's all zero), there's nothing to verify against and
	// this returns true so callers don't refuse a launch on a brand-new
	// online account.
	[[nodiscard]] bool VerifyPlaintextPassword(std::string_view plaintext) const;

	// Mutates the cached Account entry matching `persistent_id`. Returns false
	// if no such account is loaded. Used by the launch-time password prompt.
	static bool ApplyPasswordToAccount(uint32 persistent_id, std::string_view plaintext, bool persist);

	// Clears m_account_password_cache to zero and sets IsPasswordCacheEnabled=0
	// for the cached Account matching `persistent_id`. When `persist` is true
	// the change is written back to account.dat. Returns false if no such
	// account is loaded. Used by the "remove password cache" action in
	// General Settings -> Account.
	static bool ClearPasswordCacheForAccount(uint32 persistent_id, bool persist);

	// this will always return at least one account (default one)
	static const std::vector<Account>& RefreshAccounts();
	static void UpdatePersisidDat();
	
	[[nodiscard]] static bool HasFreeAccountSlots();
	[[nodiscard]] static const std::vector<Account>& GetAccounts();
	[[nodiscard]] static const Account& GetAccount(uint32 persistent_id);
	[[nodiscard]] static const Account& GetCurrentAccount();
	[[nodiscard]] static uint32 GetNextPersistentId();
	[[nodiscard]] static fs::path GetFileName(uint32 persistent_id);
	[[nodiscard]] OnlineValidator ValidateOnlineFiles() const;
private:
	Account(uint32 persistent_id);

	[[nodiscard]] std::error_code CheckValid() const;
	void ParseFile(class FileStream* file);

	uint32 m_persistent_id = 0;
	uint64 m_transferable_id_base = 0;
	std::array<uint8, 16> m_uuid {};
	std::array<uint8, 96> m_mii_data{};
	std::array<wchar_t, 11> m_mii_name{};
	std::string m_account_id;

	uint16 m_birth_year = 0;
	uint8 m_birth_month = 0;
	uint8 m_birth_day = 0;
	uint8 m_gender = 0;

	std::string m_email;
	uint32 m_country = 0;
	uint32 m_simple_address_id = 0;
	std::string m_timezone_id;
	sint64 m_utc_offset;
	uint32 m_principal_id = 0;
	uint8 m_password_cache_enabled = 0;
	std::array<uint8, 32> m_account_password_cache{};
	// In-memory only - never persisted, never parsed from account.dat.
	bool m_session_password_filled = false;

	// misc storage for unused local properties
	std::unordered_map<std::string, std::string> m_storage;

	static std::vector<Account> s_account_list;
};
