// Copyright (C) 2025 Evan McBroom
#pragma once
#include <cstddef>
#include <string>
#include <vector>

std::vector<uint8_t> CalculateNtOwfPassword(const std::string& password);
std::vector<uint8_t> HashMessage(const std::wstring& algoType, const std::vector<uint8_t>& message);
std::vector<uint8_t> HexDecode(std::ostream& out, const std::wstring& asciiHex);