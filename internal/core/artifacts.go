package core

import (
	"os"
	"path/filepath"
	"strings"
)

// linuxArtifactPaths is the Linux triage profile used by full mode.
// Password hashes (/etc/shadow) and private keys are omitted.
// /var/log is collected as a tree, so individual log files under it are not repeated.
func linuxArtifactPaths(homeRoot string, users []string) []string {
	paths := []string{
		"/etc/passwd",
		"/etc/group",
		"/etc/hosts",
		"/etc/hosts.allow",
		"/etc/hosts.deny",
		"/etc/resolv.conf",
		"/etc/fstab",
		"/etc/crontab",
		"/etc/cron.d",
		"/etc/cron.hourly",
		"/etc/cron.daily",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/var/spool/cron/crontabs",
		"/etc/sudoers",
		"/etc/sudoers.d",
		"/etc/systemd/system",
		"/etc/ssh/sshd_config",
		"/etc/ssh/ssh_config",
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/environment",
		"/etc/ld.so.preload",
		"/etc/ld.so.conf",
		"/etc/ld.so.conf.d",
		"/etc/modprobe.d",
		"/etc/modules-load.d",
		"/etc/udev/rules.d",
		"/etc/rc.local",
		"/etc/init.d",
		"/etc/sysctl.conf",
		"/etc/sysctl.d",
		"/etc/apt/sources.list",
		"/etc/apt/sources.list.d",
		"/etc/yum.repos.d",
		"/etc/pacman.conf",
		"/var/lib/dpkg/status",
		"/var/log",
		"/root/.bash_history",
		"/root/.zsh_history",
		"/root/.ssh/authorized_keys",
		"/root/.ssh/known_hosts",
		"/root/.config/autostart",
		"/root/.config/systemd/user",
	}
	names := []string{
		".bash_history", ".zsh_history", ".sh_history", ".python_history", ".mysql_history", ".wget-hsts",
		".ssh/authorized_keys", ".ssh/known_hosts", ".ssh/config",
		".config/autostart", ".config/systemd/user", ".local/share/recently-used.xbel",
	}
	for _, user := range users {
		for _, name := range names {
			paths = append(paths, filepath.Join(homeRoot, user, name))
		}
	}
	return paths
}

// windowsArtifactPaths is the Windows triage profile.
// SAM, SECURITY and ntds.dit are omitted because they hold password hashes.
func windowsArtifactPaths(root string, userHomes []string) []string {
	j := func(parts ...string) string {
		return filepath.Join(append([]string{root}, parts...)...)
	}
	paths := []string{
		j("System32", "drivers", "etc", "hosts"),
		j("System32", "drivers", "etc", "networks"),
		j("System32", "Tasks"),
		j("Tasks"),
		j("Prefetch"),
		j("System32", "winevt", "Logs"),
		j("System32", "LogFiles"),
		j("System32", "config", "SYSTEM"),
		j("System32", "config", "SOFTWARE"),
		j("System32", "config", "DEFAULT"),
		j("AppCompat", "Programs", "Amcache.hve"),
		j("System32", "sru", "SRUDB.dat"),
		j("INF", "setupapi.dev.log"),
		j("INF", "setupapi.setup.log"),
		j("Panther", "setupact.log"),
		j("Panther", "setuperr.log"),
	}
	for _, home := range userHomes {
		paths = append(paths,
			filepath.Join(home, "NTUSER.DAT"),
			filepath.Join(home, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"),
			filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
			filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "Recent"),
			filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
		)
	}
	return paths
}

// darwinArtifactPaths is the macOS triage profile.
// Unified logs are collected with log show, not by copying /var/db/diagnostics.
func darwinArtifactPaths(userHomes []string) []string {
	paths := []string{
		"/etc/passwd",
		"/etc/group",
		"/etc/hosts",
		"/etc/resolv.conf",
		"/etc/sudoers",
		"/etc/sudoers.d",
		"/etc/crontab",
		"/etc/periodic",
		"/var/log",
		"/Library/Logs",
		"/Library/LaunchAgents",
		"/Library/LaunchDaemons",
		"/Library/StartupItems",
		"/Library/Preferences/com.apple.loginwindow.plist",
		"/Library/Application Support/com.apple.TCC/TCC.db",
		"/System/Library/LaunchAgents",
		"/System/Library/LaunchDaemons",
		"/root/.bash_history",
		"/root/.zsh_history",
	}
	for _, home := range userHomes {
		paths = append(paths,
			filepath.Join(home, ".bash_history"),
			filepath.Join(home, ".zsh_history"),
			filepath.Join(home, ".zsh_sessions"),
			filepath.Join(home, ".ssh", "authorized_keys"),
			filepath.Join(home, ".ssh", "known_hosts"),
			filepath.Join(home, "Library", "LaunchAgents"),
			filepath.Join(home, "Library", "Logs"),
			filepath.Join(home, "Library", "Safari", "History.db"),
			filepath.Join(home, "Library", "Application Support", "Knowledge", "knowledgeC.db"),
			filepath.Join(home, "Library", "Application Support", "com.apple.TCC", "TCC.db"),
			filepath.Join(home, "Library", "Preferences", "com.apple.LaunchServices.QuarantineEventsV2"),
		)
	}
	return paths
}

// discoverBrowserHistories returns Chrome, Chromium, Edge and Firefox history
// files that exist. Credential stores (Login Data, Cookies, logins.json, key4.db)
// are not included.
func discoverBrowserHistories(homes []string, layout string) []string {
	var out []string
	for _, home := range homes {
		var chrome []string
		var firefox string
		switch layout {
		case "linux":
			chrome = []string{
				filepath.Join(home, ".config", "google-chrome"),
				filepath.Join(home, ".config", "chromium"),
				filepath.Join(home, ".config", "microsoft-edge"),
			}
			firefox = filepath.Join(home, ".mozilla", "firefox")
		case "darwin":
			chrome = []string{
				filepath.Join(home, "Library", "Application Support", "Google", "Chrome"),
				filepath.Join(home, "Library", "Application Support", "Chromium"),
				filepath.Join(home, "Library", "Application Support", "Microsoft Edge"),
			}
			firefox = filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")
		case "windows":
			chrome = []string{
				filepath.Join(home, "AppData", "Local", "Google", "Chrome", "User Data"),
				filepath.Join(home, "AppData", "Local", "Microsoft", "Edge", "User Data"),
			}
			firefox = filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
		default:
			return nil
		}
		for _, dir := range chrome {
			out = append(out, chromeHistoryFiles(dir)...)
		}
		out = append(out, firefoxPlaces(firefox)...)
	}
	return out
}

func chromeHistoryFiles(userData string) []string {
	entries, e := os.ReadDir(userData)
	if e != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name != "Default" && !strings.HasPrefix(name, "Profile ") {
			continue
		}
		for _, file := range []string{"History", "Bookmarks"} {
			path := filepath.Join(userData, name, file)
			if st, e := os.Stat(path); e == nil && st.Mode().IsRegular() {
				out = append(out, path)
			}
		}
	}
	return out
}

func firefoxPlaces(dir string) []string {
	entries, e := os.ReadDir(dir)
	if e != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name(), "places.sqlite")
		if st, e := os.Stat(path); e == nil && st.Mode().IsRegular() {
			out = append(out, path)
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
