
#pragma once

// Hex helper functions:
// Copied from EVMC: Ethereum Client-VM Connector API.
// No functionality modification expected.
// Copyright 2021 The EVMC Authors.
// Licensed under the Apache License, Version 2.0.

namespace erc2o {

/// Extracts the nibble value out of a hex digit.
/// Returns -1 in case of invalid hex digit.
inline constexpr int from_hex_digit(char h) noexcept {
    if (h >= '0' && h <= '9')
        return h - '0';
    else if (h >= 'a' && h <= 'f')
        return h - 'a' + 10;
    else if (h >= 'A' && h <= 'F')
        return h - 'A' + 10;
    else
        return -1;
}

/// Decodes hex-encoded sequence of characters.
///
/// It is guaranteed that the output will not be longer than half of the input length.
///
/// @param begin  The input begin iterator. It only must satisfy input iterator concept.
/// @param end    The input end iterator. It only must satisfy input iterator concept.
/// @param out    The output iterator. It must satisfy output iterator concept.
/// @return       True if successful, false if input is invalid hex.
template <typename InputIt, typename OutputIt>
inline constexpr bool from_hex(InputIt begin, InputIt end, OutputIt out) noexcept {
    int hi_nibble = -1;  // Init with invalid value, should never be used.
    size_t i = 0;
    for (auto it = begin; it != end; ++it, ++i) {
        const auto h = *it;
        const int v = from_hex_digit(h);
        if (v < 0) {
            if (i == 1 && hi_nibble == 0 && h == 'x')  // 0x prefix
                continue;
            return false;
        }

        if (i % 2 == 0)
            hi_nibble = v << 4;
        else
            *out++ = static_cast<uint8_t>(hi_nibble | v);
    }

    return i % 2 == 0;
}

/// Decodes hex encoded string to bytes.
///
/// In case the input is invalid the returned value is std::nullopt.
/// This can happen if a non-hex digit or odd number of digits is encountered.
inline std::optional<bytes> from_hex(std::string_view hex) {
    bytes bs;
    bs.reserve(hex.size() / 2);
    if (!from_hex(hex.begin(), hex.end(), std::back_inserter(bs)))
        return {};
    return bs;
}

}  // namespace erc2o