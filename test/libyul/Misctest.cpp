#include "libyul/backends/evm/ssa/AStarShuffler.h"
#include "libyul/backends/evm/ssa/OperationForwardShuffler.h"


#include <boost/test/unit_test.hpp>
#include <fmt/ranges.h>

#include <libyul/backends/evm/SSACFGStackShuffler.h>
#include <libyul/backends/evm/ssa/LivenessAnalysis.h>

#include <range/v3/view/concat.hpp>

namespace
{

using SourceSlot = solidity::yul::ssa::StackSlot;
struct PrintCallback
{
	PrintCallback(std::optional<std::function<void()>> _callback=std::nullopt): callback(_callback) {}

	using Slot = SourceSlot;
	void swap(size_t _depth)
	{
		++numOps;
		if (callback)
		{
			fmt::print("swap {}: ", _depth);
			(*callback)();
		}
	}
	void dup(size_t _depth)
	{
		++numOps;
		if (callback)
		{
			fmt::print("dup {}: ", _depth);
			(*callback)();
		}
	}
	void push(Slot const&)
	{
		++numOps;
		if (callback)
		{
			fmt::print("push: ");
			(*callback)();
		}
	}
	void pop()
	{
		++numOps;
		if (callback)
		{
			fmt::print("pop: ");
			(*callback)();
		}
	}

	size_t numOps{};
	std::optional<std::function<void()>> callback;
};

using TestStack = solidity::yul::ssa::Stack<PrintCallback>;



}

namespace solidity::yul::test
{
BOOST_AUTO_TEST_SUITE(MiscTest)

BOOST_AUTO_TEST_CASE(yo)
{
	auto cfg = std::make_unique<ssa::SSACFG>();
	cfg->debugData = langutil::DebugData::create();
	cfg->entry = cfg->makeBlock(langutil::DebugData::create());
	cfg->block(cfg->entry).exit = ssa::SSACFG::BasicBlock::MainExit{};

	auto const v1 = cfg->newVariable({0});
	auto const v2 = cfg->newVariable({0});
	auto const v3 = cfg->newVariable({0});
	auto const v4 = cfg->newVariable({0});
	auto const v5 = cfg->newVariable({0});
	auto const v6 = cfg->newVariable({0});
	auto const v48 = cfg->newVariable({0});
	auto const v49 = cfg->newVariable({0});
	auto const v19 = cfg->newVariable({0});
	auto const v98 = cfg->newVariable({0});
	auto const v99 = cfg->newVariable({0});
	auto const v58 = cfg->newVariable({0});
	auto const v59 = cfg->newVariable({0});
	auto const v67 = cfg->newVariable({0});
	auto const v68 = cfg->newVariable({0});
	auto const v76 = cfg->newVariable({0});
	auto const v77 = cfg->newVariable({0});
	auto const v79 = cfg->newVariable({0});
	auto const v188 = cfg->newVariable({0});
	auto const zero = cfg->newLiteral(langutil::DebugData::create(), 0);
	auto const two = cfg->newLiteral(langutil::DebugData::create(), 2);
	auto const thirtytwo = cfg->newLiteral(langutil::DebugData::create(), 32);

	std::shared_ptr<TestStack> stack;
	PrintCallback callback([&stack, &cfg]
	{
		if (stack)
			std::cout << ssa::stackToString(stack->data(), *cfg) << std::endl;
	});

	FunctionCall funDeposit {
		.debugData = nullptr,
		.functionName = Identifier{nullptr, YulString{"fun_deposit"}},
		.arguments = {}
	};
	auto const v113 = cfg->newVariable({0});
	auto const v115 = cfg->newVariable({0});
	auto const v119 = cfg->newVariable({0});
	auto const v136 = cfg->newVariable({0});
	auto const v139 = cfg->newVariable({0});
	auto const v141 = cfg->newVariable({0});

	std::vector slotsRef {
		SourceSlot::makeValueID(v113), SourceSlot::makeValueID(v115), SourceSlot::makeValueID(v119), SourceSlot::makeValueID(v136), SourceSlot::makeValueID(v139), SourceSlot::makeValueID(v141)
	};
	ssa::LivenessAnalysis::LivenessData liveness({{v113, 1}, {v115, 1}, {v119, 1}});
	TestStack::Data args{SourceSlot::makeValueID(thirtytwo), SourceSlot::makeValueID(zero), SourceSlot::makeValueID(v139), SourceSlot::makeValueID(v136), SourceSlot::makeValueID(two), SourceSlot::makeValueID(v141)};
	std::vector<SourceSlot> final;

	{
		auto slots = slotsRef;
		stack = std::make_shared<TestStack>(slots, callback, TestStack::CanBeFreelyGenerated{});

		//   fun_deposit([JUNK x 6, v58, v59, JUNK, v67, v68, JUNK, v76, v77, v79] -> { [] } + [ReturnLabel[fun_deposit], v79, v77, v76, v68, v67, v59, v58])
		// mstore([JUNK x 7, v48, v49] -> { [v49] } + [v48, v49]) -> DUP1 + SWAP2 + SWAP1 +  -> [JUNK x 7, v49]
		// staticcall([JUNK x 5, v113, v115, v119, v136, JUNK, JUNK, v139, v141] -> { [v113, v115, v119] } + [32, 0, v139, v136, 2, v141]) -> PUSH v13 + PUSH v6 + PUSH v140 + SWAP1 + SWAP4 + SWAP3 + SWAP7 + SWAP2 + SWAP5 + SWAP7 +  -> [JUNK x 5, v113, v115, v119, JUNK, JUNK, v142]

		std::cout << fmt::format("--- start shuffle with {} ---", ssa::stackToString(stack->data(), *cfg)) << std::endl;
		// TestStack::Data args{v79, v68};
		{
			auto const t = ranges::views::transform([&](ssa::SSACFG::ValueId _valueId) { return ssa::slotToString(SourceSlot::makeValueID(_valueId), *cfg); });
			auto const t2 = ranges::views::transform([&](SourceSlot const& _slot) { return ssa::slotToString(_slot, *cfg); });
			auto r = liveness | ranges::views::keys | t;
			std::cout
				<< ">>> target: "
				<< fmt::format("{{ {} }} + ", fmt::join(r, ", "))
				<< fmt::format("[ {} ]\n", fmt::join(args | t2, ", "));
		}
		ssa::OperationForwardShuffler<TestStack>::shuffle(*stack, args, liveness, true);
		std::cout << "--- fin ---" << std::endl;
		std::cout << ssa::stackToString(stack->data(), *cfg) << std::endl;
		final = stack->data();
	}
	{
		constexpr auto SlotIsCompatible = [](TestStack::Slot const& _source, TestStack::Slot const& _target) { return _target.isJunk() || _source == _target; };
		auto slots = slotsRef;
		stack = std::make_shared<TestStack>(slots, callback, TestStack::CanBeFreelyGenerated{});
		std::cout << fmt::format("\n\nAnd now with A*:\n") << std::flush;
		TestStack::Data tail(final.begin(), final.begin() + static_cast<size_t>(final.size() - args.size()));
		ssa::BlockForwardAStarShuffler<TestStack, SlotIsCompatible>::shuffle(*stack, tail, args);
	}
	{
		auto slots = slotsRef;
		stack = std::make_shared<TestStack>(slots, callback, TestStack::CanBeFreelyGenerated{});

		std::cout << fmt::format("\n\nAnd now with Daniel shuffler:\n") << std::flush;
		DanielShuffler<TestStack>::shuffle(*stack, {}, final);
	}
}

BOOST_AUTO_TEST_SUITE_END()
}
