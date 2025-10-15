#include "AStarShuffler.h"
#include "ExactShuffler.h"
#include "libyul/backends/evm/ssa/LivenessAnalysis.h"
#include "libyul/backends/evm/SSACFGStackShuffler.h"
#include "range/v3/algorithm/count.hpp"
#include "range/v3/algorithm/equal.hpp"
#include "range/v3/algorithm/min_element.hpp"
#include "range/v3/algorithm/none_of.hpp"
#include "range/v3/algorithm/replace.hpp"
#include "range/v3/algorithm/sort.hpp"
#include "range/v3/view/drop.hpp"

#include <libyul/backends/evm/ssa/StackLayoutGenerator.h>
#include <libyul/backends/evm/ssa/OperationForwardShuffler.h>

#include <queue>
#include <ranges>

using namespace solidity::yul;
using namespace solidity::yul::ssa;

#if !defined(NDEBUG)
bool StackLayoutGenerator::StackManipulationCallbacks::writeCallbackOutput = true;
#else
bool StackLayoutGenerator::StackManipulationCallbacks::writeCallbackOutput = false;
#endif

namespace
{
#if !defined(NDEBUG)
bool constexpr debugOutput = true;
#else
bool constexpr debugOutput = false;
#endif

[[maybe_unused]] std::vector<StackLayoutGenerator::Slot> pileOfJunk(size_t const _size)
{
	return std::vector(_size, ssa::StackSlot::makeJunk());
}

/*class IsSSACFGLiteral
{
public:
	explicit IsSSACFGLiteral(SSACFG const& _cfg): m_cfg(_cfg) {}

	bool operator()(SSACFG::ValueId const _valueId) const { return m_cfg.isLiteralValue(_valueId); }
	bool operator()(SSACFGStackLayout::Slot const& _slot) const
	{
		return std::holds_alternative<SSACFG::ValueId>(_slot) && (*this)(std::get<SSACFG::ValueId>(_slot));
	}

private:
	SSACFG const& m_cfg;
};*/

void declareJunk(StackLayoutGenerator::StackType& _stack, LivenessAnalysis::LivenessData const& _live)
{
	for (size_t depth = 0; depth < _stack.size(); ++depth)
	{
		auto const slot = _stack.slot(depth);
		if (slot.isValueID() && !_live.contains(slot.valueID()))
			_stack.declareJunk(depth);
	}
}

void reduceStackToLiveness(StackLayoutGenerator::StackType& _stack, std::set<SSACFG::ValueId> const& _livenessPreImage, bool const _introduceJunk)
{
	// if we are allowed to introduce junk, we'll just declare everything in the stack tail that is not part of the liveness
	// set as junk until we find something that has relevance. That way the stack closer to the top is kept compact
	// and the end part can be safely discarded
	if (_introduceJunk)
		for (size_t i = 0; i < _stack.size(); ++i)
		{
			if (!_stack[i].isValueID() && !_stack[i].isJunk())
				break;

			if (auto const slot = _stack.slot(i); slot.isValueID())
			{
				if (_livenessPreImage.contains(slot.valueID()))
					break;
				_stack.declareJunk(_stack.size() - i - 1);
			}
		}

	// pop everything not in the combined pre image
	// we can ignore the phi function pre-image slots because they are definitely in the combined liveness
	while (
		_stack.size() > 0 &&
		_stack.top().isValueID() &&
		!_livenessPreImage.contains(_stack.top().valueID())
	)
		_stack.pop();
	for (auto it = _stack.data().rbegin(); it != _stack.data().rend(); ++it)
	{
		if (it->isValueID() && !_livenessPreImage.contains(it->valueID()))
		{
			yulAssert(it != _stack.data().rbegin()); // this shouldn't happen as we have already popped everything up front
			auto const depth = static_cast<std::size_t>(std::distance(_stack.data().rbegin(), it));
			if (depth > 0)
				_stack.swap(depth);
			_stack.pop();
		}
	}
}


}

StackLayoutGenerator::StackLayoutGenerator(LivenessAnalysis const& _liveness, TerminationPathAnalysis const& _junkBlockFinder):
	m_liveness(_liveness),
	m_cfg(_liveness.cfg()),
	m_blockHasStackInDefined(m_cfg.numBlocks(), false),
	m_junkBlockFinder(_junkBlockFinder)
{
	m_stackLayout.blockLayouts.resize(m_cfg.numBlocks());
}

SSACFGStackLayout StackLayoutGenerator::generate(LivenessAnalysis const& _cfgLiveness, TerminationPathAnalysis const& _junkBlockFinder)
{
	if constexpr (debugOutput)
		std::cout << "stack layout for "
				  << (_cfgLiveness.cfg().function ? _cfgLiveness.cfg().function->name.str() : "main graph") << '\n';
	return StackLayoutGenerator{_cfgLiveness, _junkBlockFinder}.computeStackLayout();
}
void StackLayoutGenerator::handlePhiFunctions(StackData& _stackData, ReversePhiFunctionTransform const& _phiInverse, LivenessAnalysis::LivenessData const& _liveness, SSACFG const& _cfg)
{
	// add any phi function values here that are not already contained in the stack
	for (auto const& [phi, preImage]: _phiInverse.data())
	{
		// yulAssert(nonZeroLiveIn.contains(phi));
		// v = phi^{-1}(v_phi)
		// auto const& preImage = nonZeroPreImage.data().at(phi);
		auto reversedStackData = _stackData | ranges::views::reverse;
		auto it = ranges::find(reversedStackData, Slot::makeValueID(preImage, _cfg));
		if (_liveness.contains(preImage))
		{
			// Both the phi function and the pre image are part of the live in set.
			// We check if there is more than one v.
			// If so, one of them is symbolically replaced by the phi function;
			// otherwise, we push the phi function value.
			// We must have the pre image here at least once, otherwise it's an invalid dup
			// yulAssert(it != _stackData.end());
			// auto it2 = ranges::find(_stackData.begin(), std::prev(it), Slot{preImage});
			if(ranges::count(_stackData, Slot::makeValueID(preImage, _cfg)) > 1)
				*it = Slot::makeValueID(phi, _cfg);
			else
				_stackData.emplace_back(Slot::makeValueID(phi, _cfg));
		}
		else
		{
			// replace all v with phi
			ranges::replace(_stackData, Slot::makeValueID(preImage, _cfg), Slot::makeValueID(phi, _cfg));
			// if its not contained, push it (could be derived from a literal)
			if (it == ranges::end(reversedStackData))
				_stackData.emplace_back(Slot::makeValueID(phi, _cfg));
		}
	}
}

SSACFGStackLayout const& StackLayoutGenerator::computeStackLayout()
{
	// traverse the cfg layer-wise using Kahn's algorithm
	// like this, (most of) the entry exit layouts are known when a block is processed

	// todo revisit the loop heads (back edge targets) after the first iteration

	std::vector<std::size_t> inDegreesIgnoringBackedges(m_cfg.numBlocks(), 0);

	for (SSACFG::BlockId id{0}; id.value < m_cfg.numBlocks(); ++id.value)
		for (auto const& entry: m_cfg.block(id).entries)
			if (!m_liveness.topologicalSort().backEdge(entry, id))
				inDegreesIgnoringBackedges[id.value] += 1;

	std::queue<SSACFG::BlockId> traversalQueue;
	traversalQueue.push(m_cfg.entry);

	size_t numVisited = 0;
	while (!traversalQueue.empty())
	{
		auto currentBlockId = traversalQueue.front();
		traversalQueue.pop();

		visitBlock(currentBlockId);

		m_cfg.block(currentBlockId).forEachExit([&](SSACFG::BlockId const& _exit){
			if (--inDegreesIgnoringBackedges[_exit.value] == 0)
				traversalQueue.push(_exit);
		});
		++numVisited;
	}
	yulAssert(numVisited == m_liveness.topologicalSort().preOrder().size());

	return m_stackLayout;
}

void StackLayoutGenerator::defineStackIn(SSACFG::BlockId const& _blockId)
{
	if (_blockId == m_cfg.entry)
	{
		if (!m_cfg.function)
			m_stackLayout[m_cfg.entry].stackIn = {};
		else
			m_stackLayout[m_cfg.entry].stackIn =
				m_cfg.arguments |
				ranges::views::reverse |
				ranges::views::transform([this](auto&& _variableAndValueId) -> Slot { return Slot::makeValueID(std::get<1>(_variableAndValueId), m_cfg); }) |
				ranges::to<std::vector>;
		m_blockHasStackInDefined[_blockId.value] = true;
		return;
	}

	if (m_blockHasStackInDefined[_blockId.value])
		return;

	auto const& block = m_cfg.block(_blockId);

	std::vector<std::pair<SSACFG::BlockId, StackData const*>> parentExits;
	for (auto const& entry: block.entries)
		if (m_blockHasStackInDefined[entry.value])
			parentExits.emplace_back(entry, &m_stackLayout[entry].stackOut);

	yulAssert(!parentExits.empty(), fmt::format("None of the parents of block {} were generated", _blockId));

	if (block.entries.size() == 1)
	{
		// pass through
		yulAssert(parentExits.size() == 1);
		// todo option1: shuffle junk to the bottom and/or pop it if non-junk isn't reachable
		// todo option2: pass through
		// todo option3: hard sort by usage frequency
		m_stackLayout[_blockId].stackIn = *parentExits[0].second;

		if (!block.phis.empty())
			handlePhiFunctions(m_stackLayout[_blockId].stackIn, ReversePhiFunctionTransform(m_cfg, parentExits[0].first, _blockId), m_liveness.liveIn(_blockId), m_cfg);

		/*StackType stackIn(m_stackLayout[_blockId].stackIn, {}, {&m_cfg});
		declareJunk(stackIn, liveIn);

		auto numJunk = ranges::count_if(stackIn, [](auto const& _slot) { return std::holds_alternative<ssa::JunkSlot>(_slot); });
		// junkShuffler(stackIn);
		m_stackLayout[_blockId].stackIn = pileOfJunk<Slot>(numJunk);
		{
			std::vector sortedLiveIn(liveIn.begin(), liveIn.end());
			ranges::sort(sortedLiveIn, [](auto const& l1, auto const& l2) { return std::get<1>(l1) > std::get<1>(l2); });
			for (const auto& var: sortedLiveIn | ranges::views::keys)
				if (!block.phis.contains(var) && !usedVariables.contains(var))
					unifiedStack.emplace_back(var);
		}*/
	}
	else
	{
		// we have more than one entry and need to unify or at the very least apply phi fct.
		auto const& liveIn = m_liveness.liveIn(_blockId);
		/*auto usedVariables = m_liveness.used(_blockId);

		// todo use the most fitting one
		//		from grey approach and each of the predecessor stacks
		// phis at the top
		std::vector<Slot> unifiedStack(block.phis.begin(), block.phis.end());
		// then all variables that are used
		// todo could be sorted by usage frequency
		{
			std::vector sortedUsedVars(usedVariables.begin(), usedVariables.end());
			ranges::sort(sortedUsedVars, [](auto const& l1, auto const& l2) { return std::get<1>(l1) > std::get<1>(l2); });
			for (const auto& var: sortedUsedVars | ranges::views::keys)
				if (!block.phis.contains(var))
					unifiedStack.emplace_back(var);
		}
		// then all variables that are live in but not used
		{
			std::vector sortedLiveIn(liveIn.begin(), liveIn.end());
			ranges::sort(sortedLiveIn, [](auto const& l1, auto const& l2) { return std::get<1>(l1) > std::get<1>(l2); });
			for (const auto& var: sortedLiveIn | ranges::views::keys)
				if (!block.phis.contains(var) && !usedVariables.contains(var))
					unifiedStack.emplace_back(var);
		}*/

		// todo junk

		/*StackData unifiedStack;
		for (auto targetVar : targetStackLayout) {
			// Case 1: Phi function mapping
			if (auto phiInput = getPhiMapping(targetVar, predecessorId)) {
				unifiedStack.push_back(*phiInput);
			}
			// Case 2: Direct variable (if live in this predecessor)
			else if (isLiveInPredecessor(targetVar, predecessorId)) {
				unifiedStack.push_back(targetVar);
			}
			// Case 3: Skip! (no "bottom" needed)
		}*/
		std::vector<size_t> cumulativeCosts(parentExits.size(), 1e12);
		for (size_t i = 0; i < parentExits.size(); ++i)
		{
			if (!parentExits[i].second)
				continue;
			size_t cumulativeCost = 0;
			auto referenceStackIn = *parentExits[i].second;
			{
				StackType stack(referenceStackIn, {});
				declareJunk(stack, liveIn);
			}
			handlePhiFunctions(referenceStackIn, ReversePhiFunctionTransform(m_cfg, parentExits[i].first, _blockId), liveIn, m_cfg);
			for (size_t j = 0; j < parentExits.size(); ++j)
			{
				if (j != i)
				{
					if (parentExits[j].second != nullptr)
					{
						auto otherStackIn = *parentExits[j].second;
						StackType stack(otherStackIn, {});
						shuffleStackExact(stack, referenceStackIn, m_cfg, SSACFG::Edge{parentExits[j].first, _blockId});
						cumulativeCost += stack.callbacks().numOps;
					}
				}
			}
			cumulativeCosts[i] = cumulativeCost;
		}
		auto argMin = std::distance(cumulativeCosts.begin(), ranges::min_element(cumulativeCosts));
		yulAssert(parentExits[argMin].second);
		// fmt::print(">> ARGMIN: {} (out of {})\n", argMin, cumulativeCosts.size());
		m_stackLayout[_blockId].stackIn = *parentExits[argMin].second;
		StackType stack(m_stackLayout[_blockId].stackIn, {});
		declareJunk(stack, liveIn);
		handlePhiFunctions(m_stackLayout[_blockId].stackIn, ReversePhiFunctionTransform(m_cfg, parentExits[argMin].first, _blockId), liveIn, m_cfg);
		//m_stackLayout[_blockId].stackIn = unifiedStack | ranges::views::reverse | ranges::to<std::vector>;
	}

	m_blockHasStackInDefined[_blockId.value] = true;
}

void StackLayoutGenerator::visitBlock(SSACFG::BlockId const& _blockId)
{
	defineStackIn(_blockId);
	yulAssert(m_blockHasStackInDefined[_blockId.value]);

	StackData currentStackData = m_stackLayout[_blockId].stackIn;
	StackType stack(currentStackData, {});
	bool const junkCanBeAdded = m_junkBlockFinder.blockAllowsAdditionOfJunk(_blockId);
	if constexpr (debugOutput)
		std::cout << fmt::format(
			"\tBlock {} (junk={}, stackIn={})\n", _blockId, junkCanBeAdded, stackToString(currentStackData, m_cfg));

	SSACFG::BasicBlock const& block = m_cfg.block(_blockId);

	auto const& operationsLiveOut = m_liveness.operationsLiveOut(_blockId);
	m_stackLayout[_blockId].operationIn.reserve(block.operations.size());
	for (size_t operationIndex = 0; operationIndex < block.operations.size(); ++operationIndex)
	{
		SSACFG::Operation const& operation = block.operations[operationIndex];
		LivenessAnalysis::LivenessData opLiveOut = operationsLiveOut[operationIndex];
		auto opLiveOutWithoutOutputs = opLiveOut;
		for (auto const& output: operation.outputs)
			opLiveOutWithoutOutputs.erase(output);

		if constexpr(debugOutput)
		{
			std::string const operationName = std::visit(util::GenericVisitor{
				[](SSACFG::Call const& _call) { return _call.function.get().name.str(); },
				[](SSACFG::BuiltinCall const& _call) { return _call.builtin.get().name; },
				[](SSACFG::LiteralAssignment const&) -> std::string { return "assign"; }
			}, operation.kind);
			std::cout << "\t\t" << operationName << "(" << stackToString(currentStackData, m_cfg) << " -> ";
		}

		// literals should have been pulled out a priori and now are treated as push constants
		// todo yulAssert(ranges::none_of(opLiveOut, IsSSACFGLiteral(m_cfg)));
		// todo this could actually be just a set of value id instead of slot
		std::set<SSACFG::ValueId> liveOutWithoutOutputsSet;
		for (const auto& valueId: opLiveOut | ranges::views::keys)
			liveOutWithoutOutputsSet.insert(valueId);
		liveOutWithoutOutputsSet -= operation.outputs;
		auto const liveOutWithoutOutputs = std::vector(liveOutWithoutOutputsSet.begin(), liveOutWithoutOutputsSet.end());
		std::vector<Slot> requiredStackTop;
		if (auto const* call = std::get_if<SSACFG::Call>(&operation.kind))
			if (call->canContinue)
			{
				auto const callSiteID = m_stackLayout.callSites.addCallSite(&call->call.get());
				requiredStackTop.emplace_back(Slot::makeFunctionCallReturnLabel(callSiteID));
			}
		requiredStackTop += operation.inputs | ranges::views::transform([this](auto const& _valueId) {return Slot::makeValueID(_valueId, m_cfg);});

		for (size_t depth = 0; depth < stack.size(); ++depth)
			if (stack.slot(depth).isValueID() && !liveOutWithoutOutputsSet.contains(stack.slot(depth).valueID()) && ranges::find(requiredStackTop, stack.slot(depth)) == ranges::end(requiredStackTop))
				stack.declareJunk(depth);
		/*junkShuffler(stack);*/

		// declareJunk(stack, opLiveOutWithoutOutputs );
		if constexpr(debugOutput)
			std::cout << "{ " << stackToString(liveOutWithoutOutputs | ranges::views::transform([this](auto const& _valueId) {return Slot::makeValueID(_valueId, m_cfg);}) | ranges::to<std::vector>, m_cfg) << " } + " << stackToString(requiredStackTop, m_cfg) << ") -> " << std::flush;

		OperationForwardShuffler<StackType>::shuffle(stack, requiredStackTop, opLiveOutWithoutOutputs, m_junkBlockFinder.blockAllowsAdditionOfJunk(_blockId), m_cfg);

		m_stackLayout[_blockId].operationIn.push_back(currentStackData);

		if constexpr(debugOutput)
		{
			#if !defined(NDEBUG)
			StackManipulationCallbacks::writeCallbackOutput = false;
			#endif
		}
		for (size_t i = 0; i < requiredStackTop.size(); ++i)
			stack.pop();
		for (auto const& val: operation.outputs)
			stack.push(Slot::makeValueID(val, m_cfg));

		if constexpr(debugOutput)
		{
			#if !defined(NDEBUG)
			StackManipulationCallbacks::writeCallbackOutput = true;
			#endif
			fmt::print(" -> {}\n", stackToString(currentStackData, m_cfg));
		}
	}

	if (auto const* cjump = std::get_if<SSACFG::BasicBlock::ConditionalJump>(&block.exit))
	{
		auto const& nonZeroLiveIn = m_liveness.liveIn(cjump->nonZero);
		auto const& zeroLiveIn = m_liveness.liveIn(cjump->zero);
		//auto const nonZeroUsed = m_liveness.used(cjump->nonZero);
		//auto const zeroUsed = m_liveness.used(cjump->zero);

		// todo isn't this the same as looking at the live-out of the current block!?
		LivenessAnalysis::LivenessData liveOutUnion;
		for (auto const& [liveIn, target]: { std::pair{&zeroLiveIn, cjump->zero}, std::pair{&nonZeroLiveIn, cjump->nonZero} }) {
			ReversePhiFunctionTransform transf(m_cfg, _blockId, target);
			for (auto const& [valueId, count]: *liveIn)
				liveOutUnion.insert(transf(valueId), count);
		}

		if (!liveOutUnion.contains(cjump->condition) && !stack.empty() && stack.top().isValueID() && stack.top().valueID() == cjump->condition)
		{
			// we done, condition is already on top of stack and no longer needed
		}
		else
		{
			// todo might need to compress stack if unreachable
			if (liveOutUnion.contains(cjump->condition))
			{
				// need to dup
				stack.pushOrDup(Slot::makeValueID(cjump->condition, m_cfg));
			}
			else
			{
				// can swap up
				if (auto const depth = stack.slotDepth(Slot::makeValueID(cjump->condition, m_cfg)))
					stack.swap(*depth);
				else
					stack.push(Slot::makeValueID(cjump->condition, m_cfg));
			}
		}

		// mark all as junk that are not live
		liveOutUnion.insert(cjump->condition);

		yulAssert(!stack.empty() && stack.top().isValueID() && stack.top().valueID() == cjump->condition);
		yulAssert(m_cfg.block(cjump->nonZero).phis.empty());

		m_stackLayout[cjump->nonZero].stackIn = currentStackData;
		m_stackLayout[cjump->nonZero].stackIn.pop_back(); // god-mode remove condition, we consume that with jumpi

		m_blockHasStackInDefined[cjump->nonZero.value] = true;
		// same as nonzero stack in initially
		m_stackLayout[cjump->zero].stackIn = m_stackLayout[cjump->nonZero].stackIn;
		handlePhiFunctions(m_stackLayout[cjump->zero].stackIn, ReversePhiFunctionTransform(m_cfg, _blockId, cjump->zero), zeroLiveIn, m_cfg);
		{
			StackType zeroStack(m_stackLayout[cjump->zero].stackIn, {});
			declareJunk(zeroStack, zeroLiveIn);
		}
		m_blockHasStackInDefined[cjump->zero.value] = true;
	}

	m_stackLayout[_blockId].stackOut = currentStackData;

	if constexpr (debugOutput)
		std::cout << fmt::format("\t\tstack out = {}\n", stackToString(currentStackData, m_cfg));
}
