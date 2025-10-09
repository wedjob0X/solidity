/*
	This file is part of solidity.

	solidity is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	solidity is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with solidity.  If not, see <http://www.gnu.org/licenses/>.
*/
// SPDX-License-Identifier: GPL-3.0

#pragma once
#include "SSACFG.h"


#include <cstdint>
#include <type_traits>

namespace solidity::yul
{

class AbstractAssembly;
struct FunctionCall;

namespace ssa
{

class StackSlot
{
public:
	enum struct Kind: std::uint8_t
	{
		ValueID, // u64, u32, or size_t
		LiteralValueID, // u64, u32, or size_t
		Junk, // empty
		AssemblyLabelID, // size_t
		FunctionReturnLabel // pointer
	};

	constexpr StackSlot() = default;
	constexpr StackSlot(StackSlot const&) = default;
	constexpr StackSlot(StackSlot&&) = default;
	constexpr StackSlot& operator=(StackSlot const&) = default;
	constexpr StackSlot& operator=(StackSlot&&) = default;

	constexpr bool isValueID() const noexcept { return kind() == Kind::ValueID; }
	constexpr bool isLiteralValueID() const noexcept { return kind() == Kind::LiteralValueID; }
	constexpr bool isFunctionReturnLabel() const noexcept { return kind() == Kind::FunctionReturnLabel; }
	constexpr bool isAssemblyLabelID() const noexcept { return kind() == Kind::AssemblyLabelID; }
	constexpr bool isJunk() const noexcept { return kind() == Kind::Junk; }
	constexpr Kind kind() const noexcept { return static_cast<Kind>(m_storage & KIND_MASK); }

	FunctionCall const* functionCall() const noexcept { return reinterpret_cast<FunctionCall const*>(payload()); }
	SSACFG::ValueId valueID() const noexcept { return SSACFG::ValueId{static_cast<SSACFG::ValueId::ValueType>(payload())}; }
	AbstractAssembly::LabelID assemblyLabelID() const noexcept { return AbstractAssembly::LabelID{static_cast<AbstractAssembly::LabelID>(payload())}; }
private:
	static constexpr int NUM_KIND_BITS = 3;
	static constexpr std::uint64_t KIND_MASK = (1ull << NUM_KIND_BITS) - 1;
	static constexpr std::uint64_t PAYLOAD_MASK = ~KIND_MASK;

	constexpr StackSlot(Kind const _kind, std::uint64_t const _payload):
		m_storage((_payload << NUM_KIND_BITS) | (static_cast<std::uint64_t>(_kind) & KIND_MASK))
	{}

	constexpr std::uint64_t payload() const noexcept { return m_storage >> NUM_KIND_BITS; }

	std::uint64_t m_storage;
};

// PODness of the slot
static_assert(sizeof(StackSlot) == 8, "StackSlot should be exactly 8 bytes");
static_assert(std::is_trivially_copyable_v<StackSlot>, "StackSlot must be trivially copyable");
static_assert(std::is_standard_layout_v<StackSlot>, "StackSlot must have standard layout");
static_assert(std::is_trivial_v<StackSlot>, "StackSlot must be trivial");
}
}
