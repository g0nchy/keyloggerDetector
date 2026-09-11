<div align="center">

# 🔍 keyloggerDetector

**A keylogger detector for Windows, written 100% in pure C++ with WinAPI, no third-party libraries, no frameworks.**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)
![Language](https://img.shields.io/badge/language-C%2B%2B-00599C?logo=cplusplus&logoColor=white)
![WinAPI](https://img.shields.io/badge/GUI-Win32%20API-lightgrey)
![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Made with](https://img.shields.io/badge/made%20with-%E2%98%95%20and%20paranoia-orange)

</div>

---

## 🕵️ What does it do?

`keyloggerDetector` scans every process running on your machine and assigns it a **suspicion score**, based on a handful of signals commonly seen in real keyloggers: keyboard hooks, raw input reading, missing digital signatures, windowless processes, unusual install locations, Registry autostart entries, and names that impersonate system processes.

It's not an antivirus. It doesn't delete anything, block anything, or send data anywhere. It just **watches and tells you** — the final call is always yours.

<div align="center">

| 🟢 LOW | 🟡 MEDIUM | 🔴 HIGH |
|:---:|:---:|:---:|
| Nothing unusual so far | A couple of signals, worth a look | Several signals stacked up, go check that process |

</div>

---

## ✨ Features

- 🧮 **Explained scoring**: every process shows exactly *why* it got the score it did.
- ⚡ **Multithreaded scanning with caching** from over 10 seconds down to under 2, even with 200+ processes.
- 🔎 **Live filtering** by process name.
- 📋 **Copy path / open location** with one click, from any expanded row.
- 🎨 **Modular theme system**: Default, Dark Mode, Terminal, and Win98, and others come built in. You can add your own with a plain `.ini` file!
- 🖥️ **Hand-drawn GUI** using pure WinAPI. No frameworks, no Electron, nothing beyond Windows itself.
- 🎪 **A window title with a mind of its own**. Last-scan statistics, and a little marquee that scrolls in a loop, because why not.

---

## 🎨 Themes

Themes are plain `.ini` files living in a `themes/` folder next to the executable. The app ships with four, and you can add your own without touching a single line of code.

```ini
[Theme]
name=My Theme

[Colors]
background=20,20,20
separator=60,60,60
text_primary=230,230,230
text_secondary=160,160,160
```

Save it as `themes/my_theme.ini`, open the **Themes** button inside the app, and it'll be right there.

---

## 🚀 Getting started

### Requirements
- Windows 10/11
- [MinGW-w64](https://www.mingw-w64.org/) (`g++`)

### Build

```bash
windres resource.rc -O coff -o resource.o
g++ -O2 -municode -mwindows -o keyloggerDetector.exe keyloggerDetector.cpp resource.o -lpsapi -lwintrust -lshell32 -lgdi32 -lcomctl32 -lole32
```

### Run

Run it **as administrator**. Without it, several system processes will show up with less information available (Windows denies access to certain processes even to an admin account, unless it's explicitly elevated).

```bash
./keyloggerDetector.exe
```

---

## 🧠 How the score works

<div align="center">

| Signal | Points |
|---|:---:|
| Uses `SetWindowsHookEx` (global keyboard hook) | +30 |
| Uses `GetAsyncKeyState` / `GetKeyState` | +20 |
| Uses the Raw Input API | +20 |
| No visible window | +15 |
| Located in a sketchy folder (Temp, AppData, Downloads) | +15 |
| No valid digital signature | +10 |
| System-sounding process name in the wrong location | +10 |
| Has a Registry autostart entry | +10 |

</div>

No single signal is proof of anything on its own, it's the **combination** that starts telling a story.

---

## ⚠️ Limitations (to be honest)

This is an educational project, built to learn WinAPI from the ground up, not a certified security product. In particular:

- It's **static analysis**: it won't catch a keylogger injected as a DLL inside another legitimate process.
- False positives happen. An unsigned process running from your projects folder isn't, by itself, a keylogger.
- Without administrator privileges, several system processes can't be fully inspected.

---

## 📜 License

This project is licensed under the **GNU General Public License v3.0**. You're free to use, modify, and redistribute it, as long as any derivative work stays just as free. See [`LICENSE`](LICENSE) for the full text.

---

<div align="center">

`.:*~*:._.-->` made by **[g0nchy](https://github.com/g0nchy)** `<--.-:*~*:.`

</div>
