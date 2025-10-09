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
#include "ControlFlow.h"
#include "SSACFG.h"
#include "libyul/backends/evm/AbstractAssembly.h"
#include "range/v3/algorithm/count_if.hpp"
#include "range/v3/view/reverse.hpp"

#include <range/v3/algorithm/find.hpp>


#include <cstdint>
#include <type_traits>

namespace solidity::yul
{

class AbstractAssembly;
struct FunctionCall;

namespace ssa
{

class CallSites
{
public:
	using CallSiteID = std::uint32_t;

	std::optional<CallSiteID> callSiteID(FunctionCall const* _functionCall) const
	{
		if (auto const it = ranges::find(m_data, _functionCall); it != m_data.end())
			return static_cast<CallSiteID>(std::distance(m_data.begin(), it));
		return std::nullopt;
	}

	FunctionCall const* functionCall(CallSiteID _callSite) const
	{
		yulAssert(_callSite < m_data.size());
		return m_data[_callSite];
	}

	CallSiteID addCallSite(FunctionCall const* _functionCall)
	{
		if (auto const id = callSiteID(_functionCall))
			return *id;
		m_data.emplace_back(_functionCall);
		return m_data.size() - 1;
	}
private:
	std::vector<FunctionCall const*> m_data;
};

class StackSlot
{
public:
	enum struct Kind: std::uint8_t
	{
		ValueID, // u32
		Junk, // empty
		FunctionCallReturnLabel, // index into corresponding stack layout's call sites
		FunctionReturnLabel // identifying the function graph via ControlFlow
	};

	constexpr StackSlot() = default;
	constexpr StackSlot(StackSlot const&) = default;
	constexpr StackSlot(StackSlot&&) = default;
	constexpr StackSlot& operator=(StackSlot const&) = default;
	constexpr StackSlot& operator=(StackSlot&&) = default;

	constexpr bool isValueID() const noexcept { return kind() == Kind::ValueID; }
	constexpr bool isFunctionReturnLabel() const noexcept { return kind() == Kind::FunctionReturnLabel; }
	constexpr bool isFunctionCallReturnLabel() const noexcept { return kind() == Kind::FunctionCallReturnLabel; }
	constexpr bool isJunk() const noexcept { return kind() == Kind::Junk; }
	constexpr Kind kind() const noexcept { return m_kind; }

	ControlFlow::FunctionGraphID functionReturnLabel() const noexcept { return m_payload; }
	SSACFG::ValueId valueID() const noexcept { return SSACFG::ValueId{static_cast<SSACFG::ValueId::ValueType>(m_payload)}; }
	CallSites::CallSiteID functionCallReturnLabel() const noexcept { return m_payload; }

	static constexpr StackSlot makeJunk() { return {Kind::Junk, 0}; }
	static constexpr StackSlot makeValueID(SSACFG::ValueId const& _valueID) { return {Kind::ValueID, _valueID.value}; }
	static constexpr StackSlot makeFunctionReturnLabel(ControlFlow::FunctionGraphID const _graphID) { return {Kind::FunctionReturnLabel, _graphID}; }
	static constexpr StackSlot makeFunctionCallReturnLabel(CallSites::CallSiteID const _callSiteID) { return {Kind::FunctionCallReturnLabel, _callSiteID};	}

	bool operator<(StackSlot const& _other) const
	{
		if (m_kind != _other.m_kind)
			return m_kind < _other.m_kind;

		return m_payload < _other.m_payload;
	}

	auto operator<=>(StackSlot const&) const = default;
private:
	constexpr StackSlot(Kind const _kind, std::uint32_t const _payload):
		m_kind(_kind),
		m_payload(_payload)
	{}

	Kind m_kind;
	std::uint32_t m_payload;
};

// PODness of the slot
static_assert(sizeof(StackSlot) == 8, "StackSlot should be exactly 8 bytes");
static_assert(std::is_trivially_copyable_v<StackSlot>, "StackSlot must be trivially copyable");
static_assert(std::is_standard_layout_v<StackSlot>, "StackSlot must have standard layout");
static_assert(std::is_trivial_v<StackSlot>, "StackSlot must be trivial");

using StackData = std::vector<StackSlot>;
std::string slotToString(StackSlot const& _slot);
std::string slotToString(StackSlot const& _slot, SSACFG const& _cfg);
std::string stackToString(StackData const& _stackData, SSACFG const& _cfg);
std::string stackToString(StackData const& _stackData);

template<typename CanBeFreelyGenerated>
concept CanBeFreelyGeneratedConcept = requires(
	CanBeFreelyGenerated _canBeFreelyGenerated,
	StackSlot _slot
)
{
	{ _canBeFreelyGenerated(_slot) } -> std::same_as<bool>;
};

struct SlotCanBeFreelyGenerated
{
	bool operator()(StackSlot const& _slot) const
	{
		if (_slot.isValueID())
			return m_cfg->isLiteralValue(_slot.valueID());
		return _slot.isJunk() || _slot.isFunctionReturnLabel() || _slot.isFunctionCallReturnLabel();
	}

	SSACFG const* m_cfg;
};
static_assert(CanBeFreelyGeneratedConcept<SlotCanBeFreelyGenerated>);

template<typename StackManipulationCallback>
concept StackManipulationCallbackConcept = requires(
	StackManipulationCallback& _callback,
	StackSlot _slot,
	size_t _depth
)
{
	{ _callback.swap(_depth) } -> std::same_as<void>;
	{ _callback.dup(_depth) } -> std::same_as<void>;
	{ _callback.push(_slot) } -> std::same_as<void>;
	{ _callback.pop() } -> std::same_as<void>;
};

struct NoOpStackManipulationCallbacks
{
	static void swap(size_t) {}
	static void dup(size_t) {}
	static void push(StackSlot const&) {}
	static void pop() {}
};
static_assert(StackManipulationCallbackConcept<NoOpStackManipulationCallbacks>);

template<
	StackManipulationCallbackConcept CallbacksType = NoOpStackManipulationCallbacks,
	CanBeFreelyGeneratedConcept CanBeFreelyGeneratedType = SlotCanBeFreelyGenerated
>
class Stack
{
	static size_t constexpr reachableStackDepth = 16;
public:
	using Callbacks = CallbacksType;
	using CanBeFreelyGenerated = CanBeFreelyGeneratedType;

	using Slot = StackSlot;
	using Data = StackData;

	Stack(
		Data& _data,
		Callbacks _callbacks,
		CanBeFreelyGenerated _canBeFreelyGenerated
	):
		m_data(&_data),
		m_callbacks(std::move(_callbacks)),
		m_canBeFreelyGenerated(std::move(_canBeFreelyGenerated))
	{}

	Slot const& top() const
	{
		yulAssert(!m_data->empty());
		return m_data->back();
	}

	void swap(size_t const _depth)
	{
		yulAssert(m_data->size() > _depth);
		yulAssert(1 <= _depth && _depth <= reachableStackDepth);
		std::swap((*m_data)[m_data->size() - _depth - 1], m_data->back());
		if constexpr (!std::is_same_v<Callbacks, NoOpStackManipulationCallbacks>)
			m_callbacks.swap(_depth);
	}

	template<bool callback=true>
	void pop()
	{
		yulAssert(!m_data->empty());
		m_data->pop_back();
		if constexpr (callback && !std::is_same_v<Callbacks, NoOpStackManipulationCallbacks>)
			m_callbacks.pop();
	}

	template<bool callback=true>
	void push(Slot const& _slot)
	{
		m_data->emplace_back(_slot);
		if constexpr (callback && !std::is_same_v<Callbacks, NoOpStackManipulationCallbacks>)
			m_callbacks.push(_slot);
	}

	void declareJunk(size_t const _depth)
	{
		yulAssert(_depth < m_data->size());
		(*m_data)[m_data->size() - _depth - 1] = Slot::makeJunk();
	}

	Slot const& slot(size_t const _depth) const
	{
		yulAssert(_depth < m_data->size());
		return (*m_data)[m_data->size() - _depth - 1];
	}

	void dup(Slot const& _slot)
	{
		std::optional<size_t> const depth = slotDepth(_slot);
		yulAssert(depth, fmt::format("Invalid dup, could not find slot"));
		yulAssert(1 <= *depth + 1 && *depth + 1 <= reachableStackDepth, "Stack too deep");
		m_data->push_back((*m_data)[m_data->size() - *depth - 1]);
		if constexpr (!std::is_same_v<Callbacks, NoOpStackManipulationCallbacks>)
			m_callbacks.dup(*depth + 1);
	}

	void pushOrDup(Slot const& _slot)
	{
		// todo this is not optimal: sometimes i want to dup even if i could push
		auto const maybeSlot = slotDepth(_slot);
		if (!(maybeSlot && maybeSlot.value() < reachableStackDepth) && canBeFreelyGenerated(_slot))
			push(_slot);
		else
			dup(_slot);
	}

	bool empty() const { return size() == 0; }

	size_t size() const
	{
		return m_data->size();
	}

	std::optional<size_t> slotDepth(Slot const& _value) const
	{
		return util::findOffset((*m_data) | ranges::views::reverse, _value);
	}

	bool canBeFreelyGenerated(Slot const& _slot) const
	{
		return m_canBeFreelyGenerated(_slot);
	}

	Slot const& operator[](size_t const _index) const { return (*m_data)[_index]; }
	auto begin() const { return ranges::begin(*m_data); }
	auto end() const { return ranges::end(*m_data); }

	size_t numJunkSlots() const
	{
		return static_cast<size_t>(ranges::count_if(*m_data, [](Slot const& _slot) { return _slot.isJunk(); } ));
	}

	void addJunkTail(std::ptrdiff_t const _numJunk)
	{
		yulAssert(_numJunk >= 0);
		if (_numJunk == 0)
			return;

		// append junk (so it's at the stack top)
		m_data->resize(m_data->size() + static_cast<std::size_t>(_numJunk));
		std::fill_n(m_data->rbegin(), static_cast<std::size_t>(_numJunk), Slot::makeJunk());
		// rotate to the right by numJunk elements, now they're in the tail
		std::rotate(m_data->rbegin(), m_data->rbegin() + static_cast<std::ptrdiff_t>(_numJunk), m_data->rend());
	}

	Data const& data() const
	{
		return *m_data;
	}

	CanBeFreelyGenerated const& canBeFreelyGeneratedFunction() const
	{
		return m_canBeFreelyGenerated;
	}

	Callbacks const& callbacks() const { return m_callbacks; }

private:
	Data* m_data;
	Callbacks m_callbacks;
	CanBeFreelyGenerated m_canBeFreelyGenerated;
};

}
}
