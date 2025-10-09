#pragma once

#include <libyul/backends/evm/ssa/LivenessAnalysis.h>

#include <range/v3/algorithm/equal.hpp>
#include <range/v3/algorithm/find.hpp>
#include <range/v3/algorithm/none_of.hpp>
#include <range/v3/view/drop.hpp>
#include <range/v3/view/iota.hpp>
#include <range/v3/view/take.hpp>
#include <range/v3/range_concepts.hpp>

#include <cstdint>
#include <map>
#include <variant>

namespace solidity::yul::ssa
{

namespace detail
{
template<ranges::range Slots, typename Slot = ranges::range_value_t<Slots>>
std::map<Slot, size_t> histogram(Slots const& _slots)
{
	std::map<Slot, size_t> result;
	for (auto const& slot: _slots)
	{
		auto const [it, _] = result.try_emplace(slot);
		++it->second;
	}
	return result;
}
}

template<typename Stack, size_t ReachableStackDepth=16>
class OperationForwardShuffler
{
	using Slot = StackSlot;

public:
	static void shuffle(
		Stack& _stack,
		std::vector<Slot> const& _args,
		LivenessAnalysis::LivenessData const& _liveOut,
		bool _generateJunk,
		SSACFG const& _cfg
	)
	{
		yulAssert(ranges::none_of(_args, [](auto const& _slot) { return _slot.isJunk(); }));

		constexpr std::size_t maxIterations = 1000;
		std::size_t i = 0;
		for (; i < maxIterations && shuffleStep(_stack, _args, _liveOut, _generateJunk, _cfg); ++i) {}
		yulAssert(i < maxIterations, fmt::format("Maximum iterations reached on {}", stackToString(_stack.data())));
	}

private:
	static std::ptrdiff_t loss(Stack::Data const& _stackData, std::vector<Slot> const& _args, LivenessAnalysis::LivenessData const& _liveOut)
	{
		std::ptrdiff_t result = 0;

		// every correct slot in the args gets a plus, every incorrect/missing one a minus
		for (size_t i = 0; i < _args.size(); ++i)
			if (_stackData.size() > i && _stackData[_stackData.size() - i - 1] == _args[_args.size() - i - 1])
				++result;
			else
				--result;
		for (auto const& [liveOutValue, _]: _liveOut)
		{
			if (_stackData.size() < _args.size())
				--result;

			auto it = ranges::find(_stackData | ranges::views::reverse | ranges::views::drop(_args.size()), liveOutValue);
			if (it == ranges::end(_stackData))
				--result;
			else
				++result;
		}

		return result;
	}

	struct StackStats
	{
		StackStats(Stack const& _stack, size_t _argsRegionSize)
		{
			histogramTail = detail::histogram(_stack.data() | ranges::views::reverse | ranges::views::drop(_argsRegionSize));
			histogram = histogramTail;
			for (Slot const& argsSlot: _stack.data() | ranges::views::reverse | ranges::views::take(_argsRegionSize))
			{
				{
					auto const [it, _] = histogram.try_emplace(argsSlot);
					++it->second;
				}
				{
					auto const [it, _] = histogramArgs.try_emplace(argsSlot);
					++it->second;
				}
			}
		}

		size_t totalCount(Slot const& _slot) const
		{
			return util::valueOrDefault(histogram, _slot, static_cast<size_t>(0));
		}

		size_t argsCount(Slot const& _slot) const
		{
			return util::valueOrDefault(histogramArgs, _slot, static_cast<size_t>(0));
		}

		size_t tailCount(Slot const& _slot) const
		{
			return util::valueOrDefault(histogramTail, _slot, static_cast<size_t>(0));
		}

	private:
		std::map<Slot, size_t> histogramTail;
		std::map<Slot, size_t> histogramArgs;
		std::map<Slot, size_t> histogram;
	};

	struct Ops
	{
		Ops(Stack const& _stack, std::vector<Slot> const& _args, LivenessAnalysis::LivenessData const& _liveOut, SSACFG const& _cfg):
			stackStats(_stack, _args.size()),
			targetMinCounts(detail::histogram(_args)),
			stack(_stack),
			args(_args),
			liveOut(_liveOut)
		{
			for (auto const& _liveValueId: _liveOut | ranges::views::keys)
			{
				auto const [it, _] = targetMinCounts.try_emplace(Slot::makeValueID(_liveValueId));
				++it->second;
			}
		}

		bool argsRegionIsCorrect() const
		{
			return args.size() <= stack.size() && ranges::equal(
				stack.data().rbegin(), stack.data().rbegin() + static_cast<std::ptrdiff_t>(args.size()),
				args.rbegin(), args.rend()
			);
		}

		bool requiredInArgs(Slot const& _slot) const
		{
			return ranges::find(args, _slot) != ranges::end(args);
		}

		bool requiredInTail(Slot const& _slot) const
		{
			return _slot.isValueID() && liveOut.contains(_slot.valueID());
		}

		bool distributionIsCorrect() const
		{
			for (auto const& [targetSlot, targetMinCount]: targetMinCounts)
				if (stackStats.totalCount(targetSlot) < targetMinCount)
					return false;
			return true;
		}

		size_t targetMinCount(Slot const& _slot) const
		{
			return util::valueOrDefault(targetMinCounts, _slot, size_t{0});
		}

		size_t targetArgsCount(Slot const& _slot) const
		{
			return static_cast<size_t>(ranges::count_if(args, [&](auto const& _arg) { return _arg == _slot; }));
		}

		bool stackAdmissible() const
		{
			return argsRegionIsCorrect() && distributionIsCorrect();
		}

		bool canBePopped(Slot const& _slot) const
		{
			return stackStats.totalCount(_slot) > targetMinCount(_slot); // todo  || stack.canBeFreelyGenerated(_slot)?
		}

		bool isArgsCompatible(size_t _sourceDepth, size_t _targetDepth) const
		{
			return _sourceDepth < stack.size() && _targetDepth < args.size() && stack.slot(_sourceDepth) == args[args.size() - _targetDepth - 1];
		}

		bool isSourceCompatible(size_t _sourceDepth1, size_t _sourceDepth2) const
		{
			return _sourceDepth1 < stack.size() && _sourceDepth2 < stack.size() && stack.slot(_sourceDepth1) == stack.slot(_sourceDepth2);
		}

		bool needsMoreSlots() const
		{
			for (auto const& arg: args)
				if (stackStats.totalCount(arg) < targetMinCount(arg))
					return true;
			return false;
		}

		StackStats stackStats;
		std::map<Slot, size_t> targetMinCounts;
		Stack const& stack;
		std::vector<Slot> const& args;
		LivenessAnalysis::LivenessData const& liveOut;
	};

	// If dupping an ideal slot causes a slot that will still be required to become unreachable, then dup
	// the latter slot first.
	// @returns true, if it performed a dup.
	static bool dupDeepSlotIfRequired(Ops const& _ops, Stack& _stack, bool const _generateJunk)
	{
		// Check if the stack is large enough for anything to potentially become unreachable.
		if (_stack.size() < ReachableStackDepth - 1)
			return false;
		// Check whether any deep slot might still be needed later (i.e. we still need to reach it with a DUP or SWAP).
		for (size_t const sourceOffset: ranges::views::iota(0u, _stack.size() - (ReachableStackDepth - 1)))
		{
			auto const sourceDepth = _stack.size() - sourceOffset - 1;
			// This slot needs to be moved into args and there is no tail slot of the same kind further up in the stack.
			auto const& slot = _stack.slot(sourceDepth);
			// check if we have more of the same slot further up in the stack
			bool const neededInArgs = _ops.targetArgsCount(slot) > _ops.stackStats.argsCount(slot);
			bool const needMore = _ops.targetMinCount(slot) > _ops.stackStats.totalCount(slot);
			if (neededInArgs || needMore)
			{
				auto const [haveMoreAboveWithoutArgs, haveMoreAbove] = [&]
				{
					for (size_t offset = sourceOffset + 1; offset < _stack.size(); ++offset)
					{
						if (_stack[offset] == slot)
							return std::make_tuple(_stack.size() - offset - 1 >= _ops.args.size(), true);
					}
					return std::make_tuple(false, false);
				}();

				// if we have more of the same further above, just unconditionally skip this one
				if (haveMoreAboveWithoutArgs)
					continue;

				// if we need this in args and we have something outside args or we can introduce junk, skip it
				if ((neededInArgs && haveMoreAboveWithoutArgs) || (_generateJunk && haveMoreAbove))
					continue;

				bool const reachable = sourceDepth < ReachableStackDepth;

				if (reachable)
				{
					if (!_ops.isArgsCompatible(0, 0))
					{
						// top needs to go into tail, swap it
						_stack.swap(sourceDepth);
					}
					else
					{
						// we need more of slot, dup it
						_stack.pushOrDup(slot);
						return true;
					}
				}
				else
				{
					// try compressing the stack, first looking at the top
					if (_ops.canBePopped(_stack.top()) || _stack.top().isJunk())
					{
						_stack.pop();
						return true;
					}
					for (size_t depth = 1; depth < std::min(_stack.size(), ReachableStackDepth); ++depth)
						// junk is prioritized
						if (_stack.slot(depth).isJunk())
						{
							_stack.swap(depth);
							_stack.pop();
							return true;
						}
					for (size_t depth = 1; depth < std::min(_stack.size(), ReachableStackDepth); ++depth)
						// then check if we have too much of a variable
						if (_ops.canBePopped(_stack.slot(depth)))
						{
							_stack.swap(depth);
							_stack.pop();
							return true;
						}
					for (size_t depth = 1; depth < std::min(_stack.size(), ReachableStackDepth); ++depth)
						// worst case try popping literals and/or other stuff (return labels etc)
						if (_stack.canBeFreelyGenerated(_stack.slot(depth)))
						{
							_stack.swap(depth);
							_stack.pop();
							return true;
						}
					// todo stack too deep :(
					return false;
				}
			}
		}
		return false;
	}

	static bool shuffleStep(
		Stack& _stack,
		std::vector<Slot> const& _args,
		LivenessAnalysis::LivenessData const& _liveOut,
		bool const _generateJunk,
		SSACFG const& _cfg
	)
	{
		Ops const ops(_stack, _args, _liveOut, _cfg);

		// Check if we have the required top already
		if (ops.argsRegionIsCorrect())
		{
			// Check if any of the args are required in the tail and not there yet
			bool const argRequiredInTail = [&]
			{
				for (auto const& arg: ops.args)
					if (ops.stackStats.totalCount(arg) < ops.targetMinCount(arg))
						return true;
				return false;
			}();
			if (argRequiredInTail)
			{
				// todo whatever we have to dup might not be reachable, check the implications of this in the algorithm:
				//		we could go stack-too-deep or we could try to compress the args (which might end in a loop?)
				for (size_t depth: ranges::views::iota(0u, ops.args.size()) | ranges::views::reverse)
					if (ops.stackStats.totalCount(_stack.slot(depth)) < ops.targetMinCount(_stack.slot(depth)))
					{
						// todo what about literals? can they be in the tail?
						// shortcut: if we need more of the top and we only have two args, we can get away with
						// two ops
						if (depth == 0 && _args.size() == 2)
						{
							_stack.swap(1);
							_stack.dup(_stack.slot(1));
							return true;
						}
						_stack.pushOrDup(_stack.slot(depth));
						return true;
					}
				yulAssert(false);
			}
			yulAssert(ops.stackAdmissible(), fmt::format("No admissible stack reached: {}", stackToString(_stack.data())));
			return false;
		}

		yulAssert(!_args.empty(), "From here on out, we need slots to be required in the top. Otherwise we should've terminated already.");

		// If we no longer need the current stack top, we pop it
		if (!_stack.empty() && ops.stackStats.argsCount(_stack.top()) > ops.targetArgsCount(_stack.top()) && !ops.isArgsCompatible(0, 0) && !ops.requiredInTail(_stack.top()) && !_stack.top().isJunk())
		{
			// fmt::print(">>> POP\n");
			_stack.pop();
			return true;
		}

		// the top is either required in args or in tail or is junk or the stack is empty
		yulAssert(_stack.empty() || _stack.top().isJunk() || ops.stackStats.argsCount(_stack.top()) > 0 || ops.stackStats.tailCount(_stack.top()) > 0 || ops.isArgsCompatible(0, 0));

		// if the top is junk and popping it fixes more positions in args than not popping it, pop it, next step
		// want: [arg3, arg2, arg1]
		// have: [arg3, arg2, arg1, JUNK]
		// -> popping JUNK fixes three arg positions immediately
		if (!_stack.empty() && _stack.top().isJunk())
		{
			std::ptrdiff_t score = 0;
			// check how many positions in args are currently fine
			for (size_t depth = 0; depth < std::min(ops.args.size(), _stack.size()); ++depth)
				score += ops.isArgsCompatible(depth, depth);
			// check how many positions we'd fix by popping the top
			for (size_t depth = 0; depth < std::min(ops.args.size(), _stack.size()); ++depth)
				score -= ops.isArgsCompatible(depth + 1, depth);
			if (score < 0)
			{
				_stack.pop();
				return true;
			}
		}

		// if there is any slot that we need more of (in args), dup/push it now
		for (auto const& arg: _args)
		{
			if (ops.targetMinCount(arg) > ops.stackStats.totalCount(arg))
			{
				if (!dupDeepSlotIfRequired(ops, _stack, _generateJunk))
				{
					_stack.pushOrDup(arg);
					return true;
				}
			}
		}

		// if the top is out of position and required in args
		if (
			!_stack.empty() &&
			!ops.isArgsCompatible(0, 0) &&
			ops.stackStats.argsCount(_stack.top()) <= ops.targetArgsCount(_stack.top())
		)
		{
			// shortcut
			{
				// if the top is required in the second slot position and we require something at the top that isn’t
				// already sufficiently often in the args section and (we can introduce junk or the target top is also
				// required for the tail), try duping a deeper element
				if (ops.isArgsCompatible(0, 1) && !ops.needsMoreSlots())
				{
					if (ops.requiredInTail(_args.back()) && ops.stackStats.argsCount(_args.back()) < ops.targetArgsCount(_args.back())) //
					{
						// dup up whatever wants to be at the top
						for (size_t depth = 1; depth < ReachableStackDepth && depth < _stack.size(); ++depth)
							if (ops.isArgsCompatible(depth, 0))
							{
								if (!dupDeepSlotIfRequired(ops, _stack, _generateJunk))
								{
									_stack.dup(_stack.slot(depth));
									return true;
								}
							}
						if (_stack.canBeFreelyGenerated(_args.back()))
						{
							if (!dupDeepSlotIfRequired(ops, _stack, _generateJunk))
							{
								_stack.push(_args.back());
								return true;
							}
						}
					}
				}
			}

			// if we can introduce junk, just try to dup it up
			if (_generateJunk && dupDeepSlotIfRequired(ops, _stack, _generateJunk))
				_stack.pushOrDup(_args.back());

			// if we need more of whatever goes to the top and it's reachable, just dup it
			if (ops.targetMinCount(_args.back()) > ops.stackStats.totalCount(_args.back()))
				if (auto const depth = _stack.slotDepth(_args.back()))
					if (*depth < ReachableStackDepth)
					{
						_stack.dup(_args.back());
						return true;
					}

			// try finding a reachable out-of-position target position that, if swapped to, also fixes the top
			for (size_t depth = 1; depth < std::min(_stack.size(), ops.args.size()); ++depth)
				if (ops.isArgsCompatible(depth, 0) && ops.isArgsCompatible(0, depth) && !ops.isArgsCompatible(depth, depth))
				{
					_stack.swap(depth);
					return true;
				}

			// if the top can be freely generated and we don't already have enough of it, generate it
			if (_stack.canBeFreelyGenerated(_args.back()) && ops.stackStats.totalCount(_args.back()) < ops.targetMinCount(_args.back()))
			{
				_stack.push(_args.back());
				return true;
			}


			// otherwise take the deepest args target slot that doesn’t hold an identical value and isn't in position
			for (size_t depth = 1; depth < std::min(_stack.size(), ops.args.size()); ++depth)
				if (ops.isArgsCompatible(0, depth) && !ops.isSourceCompatible(0, depth) && !ops.isArgsCompatible(depth, depth))
				{
					_stack.swap(depth);
					return true;
				}

			// we can’t swap that deep, park current slot in a reachable slot that can be removed (too many of it or junk) and pop the head afterwards
			for (size_t depth = 1; depth < ReachableStackDepth + 1; ++depth)
				if (depth < _stack.size() && ops.canBePopped(_stack.slot(depth)))
				{
					_stack.swap(depth);
					_stack.pop();
					return true;
				}

			// try finding a reachable out-of-position arg slot that fixes the top
			for (size_t depth = 1; depth < std::min(_stack.size(), ops.args.size()); ++depth)
				if (ops.isArgsCompatible(depth, 0) && !ops.isArgsCompatible(depth, depth))
				{
					_stack.swap(depth);
					return true;
				}

			// If there is a reachable slot to be removed, park the current top there.
			for (size_t swapDepth: ranges::views::iota(1u, ReachableStackDepth + 1u) | ranges::views::reverse)
				if (swapDepth < _stack.size() && ops.canBePopped(_stack.slot(swapDepth)))
				{
					_stack.swap(swapDepth);
					_stack.pop();
					return true;
				}

			yulAssert(false, fmt::format("stack too deep: {}", stackToString(_stack.data())));
		}

		yulAssert(_stack.empty() || _stack.top().isJunk() || ops.isArgsCompatible(0, 0) || ops.requiredInTail(_stack.top()));

		// if there is a slot that needs to be swapped up or duped but is on the verge of being unreachable, try swapping/duping it
		if (dupDeepSlotIfRequired(ops, _stack, _generateJunk))
			return true;

		// If the top isn’t correct and not required in args, find a slot that is compatible with the target top and swap it up, next step
		if (!_stack.empty() && !ops.isArgsCompatible(0, 0) && ops.requiredInArgs(_stack.top()))
		{
			for (size_t depth: ranges::views::iota(1u, _stack.size()) | ranges::views::reverse)
				// It makes sense to swap to a lower position, if
				if (
					(depth >= _args.size() || !ops.isArgsCompatible(depth, depth)) && // The lower slot is not already in position.
					_stack.slot(depth) != _stack.top() && // We would not just swap identical slots.
					ops.isArgsCompatible(depth, 0) // The lower position wants to be at the top
				)
				{
					// We cannot swap that deep.
					if (depth > ReachableStackDepth)
					{
						// If there is a reachable slot to be removed, park the current top there.
						for (size_t swapDepth: ranges::views::iota(1u, ReachableStackDepth + 1u) | ranges::views::reverse)
							if (ops.canBePopped(_stack.slot(swapDepth)))
							{
								_stack.swap(swapDepth);
								if (_stack.top().isJunk())
									// Usually we keep a slot that is to-be-removed, if the current top is arbitrary.
									// However, since we are in a stack-too-deep situation, pop it immediately
									// to compress the stack (we can always push back junk in the end).
									_stack.pop();
								return true;
							}
						// Otherwise, we rely on stack compression or stack-to-memory.
					}
					_stack.swap(depth);
					return true;
				}
			if (_stack.canBeFreelyGenerated(_args.back()))
			{
				_stack.pushOrDup(_args.back());
				return true;
			}
		}

		yulAssert(_stack.empty() || ops.isArgsCompatible(0, 0) || ops.requiredInTail(_stack.top()) || _stack.top().isJunk(), fmt::format("Current stack: {}", stackToString(_stack.data())));

		// if there is any slot we need more of to populate args, dup that, next step
		for (auto const& arg: ops.args)
			if (ops.targetMinCount(arg) > ops.stackStats.totalCount(arg))
				if (!dupDeepSlotIfRequired(ops, _stack, _generateJunk))
				{
					_stack.pushOrDup(arg);
					return true;
				}

		// now all required slots are present in required quantity
		for (auto const& [targetSlot, targetSlotMinCount]: ops.targetMinCounts)
			yulAssert(ops.stackStats.totalCount(targetSlot) >= targetSlotMinCount);

		auto swappableDepthRange = ranges::views::iota(0u, std::min(ReachableStackDepth + 1u, _stack.size())) | ranges::views::reverse;

		// If we find a lower slot that is out of position, but also compatible with the top, swap that up.
		for (size_t depth: swappableDepthRange)
			if (!ops.isArgsCompatible(depth, depth) && ops.isArgsCompatible(0, depth))
			{
				_stack.swap(depth);
				return true;
			}

		// Swap up any reachable slot that is still out of position.
		for (size_t depth: swappableDepthRange)
			if (depth < _args.size())
			{
				if (!ops.isArgsCompatible(depth, depth) && _stack.slot(depth) != _stack.top())
				{
					_stack.swap(depth);
					return true;
				}
			}
			else
			{
				if (ops.requiredInArgs(_stack.slot(depth)) && ops.stackStats.argsCount(_stack.slot(depth)) < ops.targetArgsCount(_stack.slot(depth)))
				{
					_stack.swap(depth);
					return true;
				}
			}

		// We are in a stack-too-deep situation and try to reduce the stack size.
		// If the current top is merely kept since the target slot is arbitrary, pop it.
		if (ops.canBePopped(_stack.top()))
		{
			_stack.pop();
			return true;
		}

		// If any reachable slot is merely kept, since the target slot is arbitrary, swap it up and pop it.
		for (size_t depth: swappableDepthRange)
			if (_stack.slot(depth).isJunk())
			{
				_stack.swap(depth);
				_stack.pop();
				return true;
			}
		yulAssert(false, "reached final and forbidden state");
	}
};

}
