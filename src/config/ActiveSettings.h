#pragma once
#include "config/CemuConfig.h"
#include "config/NetworkSettings.h"

// global active settings for fast access (reflects settings from command line and game profile)
class ActiveSettings
{
private:
	template <typename ...TArgs>
	static fs::path GetPath(const fs::path& path, std::string_view format, TArgs&&... args)
	{
		cemu_assert_debug(format.empty() || (format[0] != '/' && format[0] != '\\'));
		std::string tmpPathStr = fmt::format(fmt::runtime(format), std::forward<TArgs>(args)...);
		return path / _utf8ToPath(tmpPathStr);
	}

	template <typename ...TArgs>
	static fs::path GetPath(const fs::path& path, std::wstring_view format, TArgs&&... args)
	{
		cemu_assert_debug(format.empty() || (format[0] != L'/' && format[0] != L'\\'));
		return path / fmt::format(fmt::runtime(format), std::forward<TArgs>(args)...);
	}
	static fs::path GetPath(const fs::path& path, std::string_view p) 
	{
		std::basic_string_view<char8_t> s((const char8_t*)p.data(), p.size());
		return path / fs::path(s);
	}
	static fs::path GetPath(const fs::path& path)
	{
		return path;
	}

public:
	// Set directories and return all directories that failed write access test
	static void
	SetPaths(bool isPortableMode,
		   const fs::path& executablePath,
		   const fs::path& userDataPath,
		   const fs::path& configPath,
		   const fs::path& cachePath,
		   const fs::path& dataPath,
		   std::set<fs::path>& failedWriteAccess);

	static void Init();

	[[nodiscard]] static fs::path GetExecutablePath() { return s_executable_path; }
	[[nodiscard]] static fs::path GetExecutableFilename() { return s_executable_filename; }
	template <typename ...TArgs>
	[[nodiscard]] static fs::path GetUserDataPath(TArgs&&... args){ return GetPath(s_user_data_path, std::forward<TArgs>(args)...); };
	template <typename ...TArgs>
	[[nodiscard]] static fs::path GetConfigPath(TArgs&&... args){ return GetPath(s_config_path, std::forward<TArgs>(args)...); };
	template <typename ...TArgs>
	[[nodiscard]] static fs::path GetCachePath(TArgs&&... args){ return GetPath(s_cache_path, std::forward<TArgs>(args)...); };
	template <typename ...TArgs>
	[[nodiscard]] static fs::path GetDataPath(TArgs&&... args){ return GetPath(s_data_path, std::forward<TArgs>(args)...); };

	[[nodiscard]] static fs::path GetMlcPath();

	template <typename ...TArgs>
	[[nodiscard]] static fs::path GetMlcPath(TArgs&&... args){ return GetPath(GetMlcPath(), std::forward<TArgs>(args)...); };
	static bool IsCustomMlcPath();
	static bool IsCommandLineMlcPath();

	// get mlc path to default cemu root dir/mlc01
	[[nodiscard]] static fs::path GetDefaultMLCPath();

private:
	inline static bool s_isPortableMode{false};
	inline static fs::path s_executable_path;
	inline static fs::path s_user_data_path;
	inline static fs::path s_config_path;
	inline static fs::path s_cache_path;
	inline static fs::path s_data_path;
	inline static fs::path s_executable_filename; // cemu.exe
	inline static fs::path s_mlc_path;

public:
	// can be called before Init
	[[nodiscard]] static bool IsPortableMode();

	// general
	[[nodiscard]] static bool LoadSharedLibrariesEnabled();
	[[nodiscard]] static bool DisplayDRCEnabled();

	// cpu
	[[nodiscard]] static CPUMode GetCPUMode();
	[[nodiscard]] static uint8 GetTimerShiftFactor();

	static void SetTimerShiftFactor(uint8 shiftFactor);
	
	// gpu
	[[nodiscard]] static PrecompiledShaderOption GetPrecompiledShadersOption();
	[[nodiscard]] static bool RenderUpsideDownEnabled();
	[[nodiscard]] static bool WaitForGX2DrawDoneEnabled();
	[[nodiscard]] static GraphicAPI GetGraphicsAPI();

	// gamma
	[[nodiscard]] static float GetTVGamma();
	[[nodiscard]] static float GetDRCGamma();

	// audio
	[[nodiscard]] static bool AudioOutputOnlyAux();
	static void EnableAudioOnlyAux(bool state);

	// account
	[[nodiscard]] static uint32 GetPersistentId();
	[[nodiscard]] static bool IsOnlineEnabled();
	[[nodiscard]] static bool HasRequiredOnlineFiles();
	[[nodiscard]] static NetworkService GetNetworkService();
	// Session-only override: when set to true, IsOnlineEnabled() reports false
	// for the rest of this title launch even if the account's configured
	// network service is Nintendo/Pretendo/Custom. Used when the user cancels
	// the launch-time password prompt and chooses to play offline. Reset to
	// false at the start of every title launch.
	static void SetForceOfflineForCurrentLaunch(bool state);
	[[nodiscard]] static bool IsForceOfflineForCurrentLaunch();
	// Session-only override of the active persistent id. When non-zero,
	// GetPersistentId() returns this value instead of the launch / config
	// setting. Set by the IOSU LoadConsoleAccount handler when the system
	// menu switches to a different account so NAPI / Account::GetCurrentAccount
	// follow the switch and online auth uses the right NNID. Reset to 0 at the
	// start of every title launch.
	static void SetSessionPersistentIdOverride(uint32 persistentId);
	[[nodiscard]] static uint32 GetSessionPersistentIdOverride();
	// dump options
	[[nodiscard]] static bool DumpShadersEnabled();
	[[nodiscard]] static bool DumpTexturesEnabled();
	[[nodiscard]] static bool DumpRecompilerFunctionsEnabled();
	[[nodiscard]] static bool DumpLibcurlRequestsEnabled();
	static void EnableDumpShaders(bool state);
	static void EnableDumpTextures(bool state);
	static void EnableDumpRecompilerFunctions(bool state);
	static void EnableDumpLibcurlRequests(bool state);

	// hacks
	[[nodiscard]] static bool VPADDelayEnabled();
	[[nodiscard]] static bool ShaderPreventInfiniteLoopsEnabled();
	[[nodiscard]] static bool FlushGPUCacheOnSwap();
	[[nodiscard]] static bool ForceSamplerRoundToPrecision();

private:
	inline static bool s_setPathsCalled = false;
	// dump options
	inline static bool s_dump_shaders = false;
	inline static bool s_dump_textures = false;
	inline static bool s_dump_recompiler_functions = false;
	inline static bool s_dump_libcurl_requests = false;

	// timer speed
	inline static uint8 s_timer_shift = 3; // right shift factor, 0 -> 8x, 3 -> 1x, 4 -> 0.5x

	// debug
	inline static bool s_audio_aux_only = false;

	inline static bool s_has_required_online_files = false;

	// Session-only "play offline" override; see SetForceOfflineForCurrentLaunch.
	inline static bool s_force_offline_session = false;

	// Session-only "current account" override; see SetSessionPersistentIdOverride.
	// 0 means "no override".
	inline static uint32 s_session_persistent_id_override = 0;
};

