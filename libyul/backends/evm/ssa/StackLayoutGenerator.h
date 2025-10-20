#pragma once

#include <libyul/backends/evm/ssa/TerminationPathAnalysis.h>
#include <libyul/backends/evm/ssa/LivenessAnalysis.h>
#include <libyul/backends/evm/SSACFGStackLayout.h>
#include <libyul/backends/evm/ssa/SSACFG.h>

namespace solidity::yul::ssa
{

class ReversePhiFunctionTransform;

class StackLayoutGenerator
{

public:
	using Slot = StackSlot;
	struct StackManipulationCallbacks
	{
		static bool writeCallbackOutput;
		size_t numOps = 0;
		void swap(size_t _depth)
		{
			++numOps;
			if (writeCallbackOutput)
				std::cout << "SWAP" << _depth << std::flush << " + ";
		}
		void dup(size_t _depth)
		{
			++numOps;
			if (writeCallbackOutput)
				std::cout << "DUP" << _depth << std::flush << " + ";
		}
		void push(Slot const& _slot)
		{
			++numOps;
			if (writeCallbackOutput)
				std::cout << "PUSH " << slotToString(_slot) << std::flush << " + ";
		}
		void pop()
		{
			++numOps;
			if (writeCallbackOutput)
				std::cout << "POP" << std::flush << " + ";
		}
	};
	using StackType = Stack<StackManipulationCallbacks>;
	using StackData = StackType::Data;

	// static ControlFlowLayout generate(ControlFlowLiveness const& _controlFlowLiveness);
	static SSACFGStackLayout generate(LivenessAnalysis const& _cfgLiveness, TerminationPathAnalysis const& _junkBlockFinder);

private:
	static void handlePhiFunctions(StackData& _stackData, ReversePhiFunctionTransform const& _phiInverse, LivenessAnalysis::LivenessData const& _liveness);

	explicit StackLayoutGenerator(LivenessAnalysis const& _liveness, TerminationPathAnalysis const& _junkBlockFinder);

	SSACFGStackLayout const& computeStackLayout();
	void defineStackIn(SSACFG::BlockId const& _blockId);
	void visitBlock(SSACFG::BlockId const& _blockId);

	LivenessAnalysis const& m_liveness;
	SSACFG const& m_cfg;

	std::vector<bool> m_blockHasStackInDefined;
	TerminationPathAnalysis const& m_junkBlockFinder;

	SSACFGStackLayout m_stackLayout;
};

}
