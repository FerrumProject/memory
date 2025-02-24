#pragma once

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <windows.h>
#include <winnt.h>

#include <psapi.h>
#include <sstream>
#include <tlhelp32.h>
#include <unordered_map>
#include <vector>

struct HandleDeleter {
  template <typename T> constexpr void operator()(T *handle) const {
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
      CloseHandle(handle);
    }
  }
};

template <std::size_t Size> struct CString_t {
  char data[Size]{};

  consteval CString_t(const char (&str)[Size]) {
    std::ranges::copy_n(str, Size, data);
  }

  static constexpr std::size_t size = Size;
};

class Pattern {
  uintptr_t m_address;

public:
  Pattern(uintptr_t address) : m_address(address) {}

  Pattern &add(uintptr_t value) {
    if (!this->is_valid()) {
      return *this;
    }

    m_address += value;

    return *this;
  }

  Pattern &fix_mov() {
    if (!this->is_valid()) {
      return *this;
    }

    this->m_address += *reinterpret_cast<int32_t *>(m_address + 3) + 7;

    return *this;
  }

  uintptr_t get() { return this->m_address; }

  bool is_valid() {
    if (this->m_address) {
      return true;
    }

    return false;
  }
};

class Scanner {
  HANDLE m_proc;
  LPVOID m_base;
  DWORD m_size;

  std::optional<std::vector<uint8_t>> read_memory() const {
    std::vector<uint8_t> buffer(m_size);
    SIZE_T bytes_read;

    if (!ReadProcessMemory(m_proc, m_base, buffer.data(), m_size,
                           &bytes_read) ||
        bytes_read != m_size) {
      return std::nullopt;
    }
    return buffer;
  }

public:
  Scanner(HANDLE proc, LPVOID base, DWORD size)
      : m_proc(proc), m_base(base), m_size(size) {}

  template <typename MaskType>
  Pattern find_pattern_impl(const MaskType &mask,
                            std::span<const uint8_t> pattern,
                            std::span<const uint8_t> buffer) const {
    const size_t pattern_size = pattern.size();
    if (pattern_size == 0 || buffer.size() < pattern_size) {
      return 0;
    }

    std::vector<size_t> x_positions;
    for (size_t j = 0; j < pattern_size; ++j) {
      if (mask[j] == 'x') {
        x_positions.push_back(j);
      }
    }

    if (x_positions.empty()) {
      return Pattern(reinterpret_cast<uintptr_t>(m_base));
    }

    std::sort(x_positions.begin(), x_positions.end(), std::greater<size_t>());

    const size_t shift_pos = x_positions.front();
    const size_t last_pos = buffer.size() - pattern_size;

    for (size_t i = 0; i <= last_pos;) {
      if (buffer[i + shift_pos] != pattern[shift_pos]) {
        i += shift_pos + 1;
        continue;
      }

      bool match = true;
      for (size_t x_j : x_positions) {
        if (buffer[i + x_j] != pattern[x_j]) {
          match = false;
          break;
        }
      }

      if (match) {
        return Pattern(reinterpret_cast<uintptr_t>(m_base) + i);
      }

      ++i;
    }

    return 0;
  }

  Pattern find_pattern(const std::string &mask,
                       const std::vector<uint8_t> &bytes) const {
    if (bytes.empty() || bytes.size() != mask.size())
      return 0;

    auto buffer = read_memory();
    if (!buffer)
      return 0;

    return find_pattern_impl(mask, bytes, buffer.value());
  }

  template <CString_t mask>
  Pattern find_pattern(const std::vector<uint8_t> &bytes) const {
    constexpr auto mask_str = mask.data;
    constexpr size_t mask_size = mask.size - 1;

    if (bytes.size() != mask_size)
      return 0;

    auto buffer = read_memory();
    if (!buffer)
      return 0;

    return find_pattern_impl(std::string_view(mask_str, mask_size), bytes,
                             buffer.value());
  }

  Pattern find_pattern(const std::string &pattern) const {
    std::vector<uint8_t> bytes;
    std::string mask;
    std::istringstream iss(pattern);
    std::string token;

    while (iss >> token) {
      if (token == "??") {
        bytes.push_back(0x00);
        mask += '?';
      } else {
        try {
          bytes.push_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16)));
          mask += 'x';
        } catch (...) {
          return 0;
        }
      }
    }

    return find_pattern(mask, bytes);
  }
};

class Module {
  HMODULE m_module;
  LPVOID m_base;
  DWORD m_size;
  Scanner m_scanner;

public:
  Module(HANDLE proc, HMODULE module, LPVOID base, DWORD size)
      : m_module(module), m_base(base), m_size(size),
        m_scanner(proc, base, size) {}

  Module(Module &&other) noexcept
      : m_module(other.m_module), m_base(other.m_base), m_size(other.m_size),
        m_scanner(std::move(other.m_scanner)) {}

  Module &operator=(Module &&other) noexcept {
    if (this != &other) {
      m_module = other.m_module;
      m_base = other.m_base;
      m_size = other.m_size;
      m_scanner = std::move(other.m_scanner);
    }
    return *this;
  }

  Module(const Module &) = delete;
  Module &operator=(const Module &) = delete;

  const Scanner &scanner() const noexcept { return m_scanner; }

  DWORD size() const noexcept { return m_size; }
  LPVOID address() const noexcept { return m_base; }
};

class Modules
    : public std::unordered_map<std::string, std::unique_ptr<Module>> {
  HANDLE m_proc;

public:
  Modules(HANDLE proc) : m_proc(proc) { update(); }

  void update() {
    clear();

    HMODULE mods[1024];
    DWORD needed;
    if (EnumProcessModules(m_proc, mods, sizeof(mods), &needed)) {
      DWORD count = needed / sizeof(HMODULE);
      for (DWORD i = 0; i < count; ++i) {
        MODULEINFO info{};
        if (GetModuleInformation(m_proc, mods[i], &info, sizeof(info))) {
          char name[MAX_PATH];
          if (GetModuleBaseName(m_proc, mods[i], name, sizeof(name))) {
            this->try_emplace(std::string(name),
                              std::make_unique<Module>(m_proc, mods[i],
                                                       info.lpBaseOfDll,
                                                       info.SizeOfImage));
          }
        }
      }
    }
  }

  Module *get_module(const std::string &name) {
    auto it = this->find(name);
    if (it != this->end()) {
      return it->second.get();
    }

    return nullptr;
  }
};

class Process {
  std::unique_ptr<void, HandleDeleter> m_proc;
  DWORD m_pid;

  Modules m_modules;

  void open_process(const std::string &name,
                    DWORD accesses = PROCESS_ALL_ACCESS) {
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!snapshot) {
      throw std::runtime_error("Failed to create snapshot");
    }

    bool found = false;
    if (Process32First(snapshot, &entry)) {
      do {
        if (_stricmp(entry.szExeFile, name.c_str()) == 0) {
          m_pid = entry.th32ProcessID;
          auto opened_handle = OpenProcess(accesses, FALSE, m_pid);
          m_proc.reset(opened_handle);
          m_modules = Modules(m_proc.get());
          found = true;
          break;
        }
      } while (Process32Next(snapshot, &entry));
    }

    if (!found) {
      throw std::runtime_error("Process not found");
    }

    if (!m_proc) {
      throw std::runtime_error("Failed to open process");
    }
  }

public:
  Process()
      : m_proc(GetCurrentProcess()), m_pid(GetCurrentProcessId()),
        m_modules(m_proc.get()) {}

  Process(const std::string &name, DWORD accesses = PROCESS_ALL_ACCESS)
      : m_proc(GetCurrentProcess()), m_modules(m_proc.get()) {
    open_process(name, accesses);
  }

  Modules &modules() { return m_modules; }

  bool write_memory_raw(uintptr_t address, LPCVOID data, SIZE_T size) const {
    SIZE_T bytes_written = 0;
    return WriteProcessMemory(m_proc.get(), reinterpret_cast<LPVOID>(address),
                              data, size, &bytes_written) &&
           bytes_written == size;
  }

  template <typename T>
  void write_memory(uintptr_t address, const T &value) const {
    if (!write_memory_raw(address, &value, sizeof(T))) {
      throw std::runtime_error(
          std::string("Failed to write memory at address: ")
              .append(std::to_string(address)));
    }
  }

  bool read_memory_raw(uintptr_t address, LPVOID buffer, SIZE_T size) const {
    SIZE_T bytes_read = 0;
    return ReadProcessMemory(m_proc.get(), reinterpret_cast<LPCVOID>(address),
                             buffer, size, &bytes_read) &&
           bytes_read == size;
  }

  template <typename T> T read_memory(uintptr_t address) const {
    T buffer;
    if (!read_memory_raw(address, &buffer, sizeof(T))) {
      throw std::runtime_error(std::string("Failed to read memory at address: ")
                                   .append(std::to_string(address)));
    }
    return buffer;
  }
};