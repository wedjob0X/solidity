#include "fmt/ranges.h"
#include "range/v3/view/drop.hpp"


#include <libyul/backends/evm/ssa/Stack.h>

namespace
{
size_t junkTailSize(solidity::yul::ssa::Stack<>::Data const& _stackData)
{
	std::size_t numJunk = 0;
	auto it = _stackData.begin();
	while (it != _stackData.end() && it->isJunk())
	{
		++numJunk;
		++it;
	}
	return numJunk;
}
}

namespace solidity::yul::ssa
{

std::string slotToString(StackSlot const& _slot)
{
	switch (_slot.kind())
	{
	case StackSlot::Kind::ValueID:
		return fmt::format("v{}", _slot.valueID().value);
	case StackSlot::Kind::Junk:
		return "JUNK";
	case StackSlot::Kind::FunctionCallReturnLabel:
		return fmt::format("FunctionCallReturnLabel[{}]", _slot.functionCallReturnLabel());
	case StackSlot::Kind::FunctionReturnLabel:
		return fmt::format("ReturnLabel[{}]", _slot.functionReturnLabel());
	}
	util::unreachable();
}

std::string slotToString(StackSlot const& _slot, SSACFG const& _cfg)
{
	if (_slot.kind() == StackSlot::Kind::ValueID)
		return _cfg.valueDescription(_slot.valueID());

	return slotToString(_slot);
}

std::string stackToString(Stack<>::Data const& _stackData)
{
	auto const numJunk = junkTailSize(_stackData);
	if (numJunk > 0)
		return fmt::format(
			"[JUNK x {}, {}]",
			numJunk,
			fmt::join(_stackData | ranges::views::drop(numJunk) | ranges::views::transform([&](auto const& _slot) { return slotToString(_slot); }), ", ")
		);

	return format(
		"[{}]",
		fmt::join(_stackData | ranges::views::transform([&](auto const& _slot) { return slotToString(_slot); }), ", ")
	);
}

std::string stackToString(Stack<>::Data const& _stackData, SSACFG const& _cfg)
{
	auto const numJunk = junkTailSize(_stackData);
	if (numJunk > 0)
		return format(
			"[JUNK x {}, {}]",
			numJunk,
			fmt::join(_stackData | ranges::views::drop(numJunk) | ranges::views::transform([&](auto const& _slot) { return slotToString(_slot, _cfg); }), ", ")
		);

	return format(
		"[{}]",
		fmt::join(_stackData | ranges::views::transform([&](auto const& _slot) { return slotToString(_slot, _cfg); }), ", ")
	);
}

}
