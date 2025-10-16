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

#include <libyul/backends/evm/EVMDialect.h>
#include <libyul/backends/evm/ssa/ControlFlow.h>
#include <libyul/backends/evm/ssa/SSACFG.h>
#include <libyul/backends/evm/SSACFGStackLayout.h>
#include <libyul/backends/evm/ssa/TerminationPathAnalysis.h>
#include <libyul/AST.h>
#include <libyul/Exceptions.h>
#include <libyul/Scope.h>

#include <libsolutil/Visitor.h>

#include <vector>

namespace solidity::langutil
{
class ErrorReporter;
}

namespace solidity::yul::ssa
{

class LivenessAnalysis;

struct AssemblyCallbacks
{
	void swap(size_t const _depth)
	{
		assembly->appendInstruction(evmasm::swapInstruction(static_cast<unsigned>(_depth)));
	}

	void pop()
	{
		assembly->appendInstruction(evmasm::Instruction::POP);
	}

	void push(StackSlot const& _slot)
	{
		switch (_slot.kind())
		{
			case StackSlot::Kind::ValueID:
			{
				auto const id = _slot.valueID();
				yulAssert(id.isLiteral(), fmt::format("Tried bringing up v{}", id.value()));
				assembly->appendConstant(cfg->literalInfo(id).value);
				return;
			}
			case StackSlot::Kind::Junk:
			{
				if (assembly->evmVersion().hasPush0())
					assembly->appendConstant(0);
				else
					assembly->appendInstruction(evmasm::Instruction::CODESIZE);
				return;
			}
			case StackSlot::Kind::FunctionCallReturnLabel:
			{
				auto const& call = callSites->functionCall(_slot.functionCallReturnLabel());
				assembly->appendLabelReference(returnLabels->at(&call));
				return;
			}
			case StackSlot::Kind::FunctionReturnLabel:
			{
				//auto const* maybeLabel = util::valueOrNullptr(*returnLabels, _label.functionCall);
				//yulAssert(maybeLabel);
				//assembly->appendLabelReference(*maybeLabel);
				// todo
				return;
			}
		}
	}

	void dup(size_t const _depth)
	{
		assembly->appendInstruction(evmasm::dupInstruction(static_cast<unsigned>(_depth)));
	}

	// ControlFlow const* controlFlow;
	SSACFG const* cfg;
	AbstractAssembly* assembly;
	CallSites const* callSites;
	std::map<FunctionCall const*, AbstractAssembly::LabelID> const* returnLabels;
};
static_assert(StackManipulationCallbackConcept<AssemblyCallbacks>);

class SSACFGEVMCodeTransform
{
public:
	using Slot = StackSlot;
	/// Use named labels for functions 1) Yes and check that the names are unique
	/// 2) For none of the functions 3) for the first function of each name.
	enum class UseNamedLabels { YesAndForceUnique, Never, ForFirstFunctionOfEachName };

	static std::vector<StackTooDeepError> run(
		AbstractAssembly& _assembly,
		ControlFlowLiveness const& _liveness,
		BuiltinContext& _builtinContext,
		UseNamedLabels _useNamedLabelsForFunctions
	);

private:
	using FunctionLabels = std::map<Scope::Function const*, AbstractAssembly::LabelID>;

	static FunctionLabels registerFunctionLabels(
		AbstractAssembly& _assembly,
		ControlFlow const& _controlFlow,
		UseNamedLabels _useNamedLabelsForFunctions
	);

	SSACFGEVMCodeTransform(
		AbstractAssembly& _assembly,
		BuiltinContext& _builtinContext,
		FunctionLabels _functionLabels,
		SSACFG const& _cfg,
		LivenessAnalysis const& _liveness
	);

	void transformFunction(Scope::Function const& _function);

	void operator()(SSACFG::BlockId _block);
	void performOperation(SSACFG::Operation const& _operation);
	void assertLayoutCompatibility(StackData const& _current, StackData const& _desired) const;

	AbstractAssembly::LabelID functionLabel(Scope::Function const& _function) const
	{
		return m_functionLabels.at(&_function);
	}

	void shuffleStack(std::vector<Slot> const& _target, std::optional<SSACFG::Edge> const& _edge = std::nullopt);

	AbstractAssembly& m_assembly;
	BuiltinContext& m_builtinContext;
	// ControlFlow const& m_controlFlow;
	SSACFG const& m_cfg;
	TerminationPathAnalysis m_junkBlockFinder;
	SSACFGStackLayout const m_stackLayout;
	std::vector<StackTooDeepError> m_stackErrors;
	AssemblyCallbacks m_assemblyCallbacks;
	StackData m_stackData;
	Stack<AssemblyCallbacks> m_stack;
	FunctionLabels const m_functionLabels;
	SSACFG::BlockId m_currentBlock;
	std::vector<std::uint8_t> m_generatedBlocks;
	std::vector<AbstractAssembly::LabelID> m_blockLabels;
	std::map<FunctionCall const*, AbstractAssembly::LabelID> m_returnLabels;
};

}
