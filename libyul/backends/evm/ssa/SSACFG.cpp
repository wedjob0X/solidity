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

#include <libyul/backends/evm/ssa/SSACFG.h>

#include <libyul/backends/evm/ssa/TerminationPathAnalysis.h>
#include <libyul/backends/evm/ssa/LivenessAnalysis.h>
#include <libyul/backends/evm/SSACFGStackLayout.h>

#include <libsolutil/StringUtils.h>
#include <libsolutil/Visitor.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtautological-compare"
#include <fmt/ranges.h>
#pragma GCC diagnostic pop

#include <range/v3/view/zip.hpp>

using namespace solidity;
using namespace solidity::util;
using namespace solidity::yul;
using namespace solidity::yul::ssa;

namespace
{
class SSACFGPrinter
{
public:
	SSACFGPrinter(SSACFG const& _cfg, SSACFG::BlockId _blockId, LivenessAnalysis const* _liveness, ssa::SSACFGStackLayout const* _stackLayout):
		m_cfg(_cfg), m_functionIndex(0), m_liveness(_liveness), m_stackLayout(_stackLayout)
	{
		if (_liveness)
			m_cfgRevertPaths = std::make_unique<TerminationPathAnalysis>(_cfg, _liveness->topologicalSort());
		printBlock(_blockId);
	}
	SSACFGPrinter(SSACFG const& _cfg, size_t _functionIndex, Scope::Function const& _function, LivenessAnalysis const* _liveness, ssa::SSACFGStackLayout const* _stackLayout):
		m_cfg(_cfg), m_functionIndex(_functionIndex), m_liveness(_liveness), m_stackLayout(_stackLayout)
	{
		if (_liveness)
			m_cfgRevertPaths = std::make_unique<TerminationPathAnalysis>(_cfg, _liveness->topologicalSort());
		printFunction(_function);
	}
	friend std::ostream& operator<<(std::ostream& stream, SSACFGPrinter const& printer) {
		stream << printer.m_result.str();
		return stream;
	}

	static std::string varToString(SSACFG const& _cfg, SSACFG::ValueId _var) {
		if (!_var.hasValue())
			return "INVALID";
		switch (_var.kind())
		{
			case SSACFG::ValueId::Kind::Literal:  return formatNumberReadable(_cfg.literalInfo(_var).value);
			case SSACFG::ValueId::Kind::Variable: return fmt::format("v{}", _var.value());
			case SSACFG::ValueId::Kind::Phi: return fmt::format("phi{}", _var.value());
			case SSACFG::ValueId::Kind::Unreachable: return "[unreachable]";
		}
		unreachable();
	}

private:
	static std::string escape(std::string_view const str)
	{
		using namespace std::literals;
		static constexpr auto replacements = std::array{std::make_tuple('$', "_d_")};
		std::stringstream ss;
		for (auto const c: str)
		{
			auto const it = std::find_if(replacements.begin(), replacements.end(), [c](auto const& replacement)
			{
				return std::get<0>(replacement) == c;
			});
			if (it != replacements.end())
				ss << std::get<1>(*it);
			else
				ss << c;
		}
		return ss.str();
	}

	std::string formatBlockHandle(SSACFG::BlockId const& _id) const
	{
		return fmt::format("Block{}_{}", m_functionIndex, _id.value);
	}

	std::string formatEdge(SSACFG::BlockId const& _v, SSACFG::BlockId const& _w, std::optional<std::string> const& _vPort = std::nullopt)
	{
		std::string const style = m_liveness && m_liveness->topologicalSort().backEdge(_v, _w) ? "dashed" : "solid";
		if (_vPort)
			return fmt::format("{}Exit:{} -> {} [style=\"{}\"];\n", formatBlockHandle(_v), *_vPort, formatBlockHandle(_w), style);
		else
			return fmt::format("{}Exit -> {} [style=\"{}\"];\n", formatBlockHandle(_v), formatBlockHandle(_w), style);
	}

	static std::string formatPhi(SSACFG const& _cfg, SSACFG::PhiValue const& _phiValue)
	{
		auto const transform = [&](SSACFG::ValueId const& valueId) { return varToString(_cfg, valueId); };
		std::vector<std::string> formattedArgs;
		formattedArgs.reserve(_phiValue.arguments.size());
		for (auto const& [arg, entry]: ranges::zip_view(_phiValue.arguments | ranges::views::transform(transform), _cfg.block(_phiValue.block).entries))
			formattedArgs.push_back(fmt::format("Block {} => {}", entry.value, arg));
		if (!formattedArgs.empty())
			return fmt::format("φ(\\l\\\n\t{}\\l\\\n)", fmt::join(formattedArgs, ",\\l\\\n\t"));
		else
			return "φ()";
	}

	void writeBlock(SSACFG::BlockId const& _id, SSACFG::BasicBlock const& _block)
	{
		auto const valueToString = [&](SSACFG::ValueId const& valueId) { return varToString(m_cfg, valueId); };
		bool entryBlock = _id.value == 0 && m_functionIndex == 0;
		if (entryBlock)
		{
			m_result << fmt::format("Entry{} [label=\"Entry\"];\n", m_functionIndex);
			m_result << fmt::format("Entry{} -> {};\n", m_functionIndex, formatBlockHandle(_id));
		}
		{
			std::string revertPathInfo;
			if (m_cfgRevertPaths)
				revertPathInfo = m_cfgRevertPaths->blockAllowsAdditionOfJunk(_id) ? "fillcolor=\"#FF746C\", style=filled, " : "";
			if (m_liveness)
			{
				m_result << fmt::format(
					"{} [{}label=\"\\\nBlock {}\\n",
					formatBlockHandle(_id),
					revertPathInfo,
					_id.value
				);
				m_result << fmt::format(
					"LiveIn: {}\\l\\\n",
					fmt::join(m_liveness->liveIn(_id) | ranges::views::transform([&](auto const& liveIn) { return valueToString(SSACFG::ValueId{liveIn.first}) + fmt::format("[{}]", liveIn.second); }), ", ")
				);
				m_result << fmt::format(
					"LiveOut: {}\\l\\\n",
					fmt::join(m_liveness->liveOut(_id) | ranges::views::transform([&](auto const& liveOut) { return valueToString(SSACFG::ValueId{liveOut.first}) + fmt::format("[{}]", liveOut.second); }), ", ")
				);
				auto const usedVariables = m_liveness->used(_id);
				m_result << fmt::format(
					"Used: {}\\l\\n",
					fmt::join(usedVariables | ranges::views::transform([&](auto const& used) { return valueToString(SSACFG::ValueId{used.first}) + fmt::format("[{}]", used.second); }), ", ")
				);
			}
			else
				m_result << fmt::format("{} [{}label=\"\\\nBlock {}\\n", formatBlockHandle(_id), revertPathInfo, _id.value);

			if (m_stackLayout)
			{
				auto const& in = m_stackLayout->blockLayouts[_id.value].stackIn;
				auto const& out = m_stackLayout->blockLayouts[_id.value].stackOut;
				m_result << fmt::format("StackIn: {}\\l\\\n", ssa::stackToString(in, m_cfg));
				m_result << fmt::format("StackOut: {}\\l\\n", ssa::stackToString(out, m_cfg));
			}

			for (auto const& phi: _block.phis)
			{
				auto const& phiInfo = m_cfg.phiInfo(phi);
				m_result << fmt::format("phi{} := {}\\l\\\n", phi.value(), formatPhi(m_cfg, phiInfo));
			}
			for (auto const& operation: _block.operations)
			{
				std::string const label = std::visit(GenericVisitor{
					[&](SSACFG::Call const& _call) {
						return _call.function.get().name.str();
					},
					[&](SSACFG::BuiltinCall const& _call) {
						return _call.builtin.get().name;
					},
					[&](SSACFG::LiteralAssignment const&)
					{
						yulAssert(operation.inputs.size() == 1);
						return varToString(m_cfg, operation.inputs.back());
					}
				}, operation.kind);
				if (!operation.outputs.empty())
					m_result << fmt::format(
						"{} := ",
						fmt::join(operation.outputs | ranges::views::transform(valueToString), ", ")
					);
				if (std::holds_alternative<SSACFG::LiteralAssignment>(operation.kind))
					m_result << fmt::format(
						"{}\\l\\\n",
						escape(label)
					);
				else
					m_result << fmt::format(
						"{}({})\\l\\\n",
						escape(label),
						fmt::join(operation.inputs | ranges::views::transform(valueToString), ", ")
					);
			}
			m_result << "\"];\n";
			std::visit(GenericVisitor{
				[&](SSACFG::BasicBlock::MainExit const&)
				{
					m_result << fmt::format("{}Exit [label=\"MainExit\"];\n", formatBlockHandle(_id));
					m_result << fmt::format("{} -> {}Exit;\n", formatBlockHandle(_id), formatBlockHandle(_id));
				},
				[&](SSACFG::BasicBlock::Jump const& _jump)
				{
					m_result << fmt::format("{} -> {}Exit [arrowhead=none];\n", formatBlockHandle(_id), formatBlockHandle(_id));
					m_result << fmt::format("{}Exit [label=\"Jump\" shape=oval];\n", formatBlockHandle(_id));
					m_result << formatEdge(_id, _jump.target);
				},
				[&](SSACFG::BasicBlock::ConditionalJump const& _conditionalJump)
				{
					m_result << fmt::format("{} -> {}Exit;\n", formatBlockHandle(_id), formatBlockHandle(_id));
					m_result << fmt::format(
						"{}Exit [label=\"{{ If {} | {{ <0> Zero | <1> NonZero }}}}\" shape=Mrecord];\n",
						formatBlockHandle(_id), varToString(m_cfg, _conditionalJump.condition)
					);
					m_result << formatEdge(_id, _conditionalJump.zero, "0");
					m_result << formatEdge(_id, _conditionalJump.nonZero, "1");
				},
				[&](SSACFG::BasicBlock::JumpTable const& jt)
				{
					m_result << fmt::format("{} -> {}Exit;\n", formatBlockHandle(_id), formatBlockHandle(_id));
					std::string options;
					for (auto const& jumpCase: jt.cases)
					{
						if (!options.empty())
							options += " | ";
						options += fmt::format("<{0}> {0}", formatNumber(jumpCase.first));
					}
					if (!options.empty())
						options += " | ";
					options += "<default> default";
					m_result << fmt::format("{}Exit [label=\"{{ JT | {{ {} }} }}\" shape=Mrecord];\n", formatBlockHandle(_id), options);
					for (auto const& jumpCase: jt.cases)
						m_result << formatEdge(_id, jumpCase.second, formatNumber(jumpCase.first));
					m_result << formatEdge(_id, jt.defaultCase, "default");
				},
				[&](SSACFG::BasicBlock::FunctionReturn const& fr)
				{
					m_result << formatBlockHandle(_id) << "Exit [label=\"FunctionReturn["
							<< fmt::format("{}", fmt::join(fr.returnValues | ranges::views::transform(valueToString), ", "))
							<< "]\"];\n";
					m_result << formatBlockHandle(_id) << " -> " << formatBlockHandle(_id) << "Exit;\n";
				},
				[&](SSACFG::BasicBlock::Terminated const&)
				{
					m_result << formatBlockHandle(_id) << "Exit [label=\"Terminated\"];\n";
					m_result << formatBlockHandle(_id) << " -> " << formatBlockHandle(_id) << "Exit;\n";
				}
			}, _block.exit);
		}
	}

	void printBlock(SSACFG::BlockId const& _rootId)
	{
		std::set<SSACFG::BlockId> explored{};
		explored.insert(_rootId);

		std::deque<SSACFG::BlockId> toVisit{};
		toVisit.emplace_back(_rootId);

		while (!toVisit.empty())
		{
			auto const id = toVisit.front();
			toVisit.pop_front();
			auto const& block = m_cfg.block(id);
			writeBlock(id, block);
			block.forEachExit(
				[&](SSACFG::BlockId const& _exitBlock)
				{
					if (explored.count(_exitBlock) == 0)
					{
						explored.insert(_exitBlock);
						toVisit.emplace_back(_exitBlock);
					}
				}
			);
		}
	}

	void printFunction(Scope::Function const& _fun)
	{
		static auto constexpr returnsTransform = [](auto const& functionReturnValue) { return escape(functionReturnValue.get().name.str()); };
		static auto constexpr argsTransform = [](auto const& arg) { return fmt::format("v{}", std::get<1>(arg).value()); };
		m_result << "FunctionEntry_" << escape(_fun.name.str()) << "_" << m_cfg.entry.value << " [label=\"";
		if (!m_cfg.returns.empty())
			m_result << fmt::format("function {0}:\n {1} := {0}({2})", escape(_fun.name.str()), fmt::join(m_cfg.returns | ranges::views::transform(returnsTransform), ", "), fmt::join(m_cfg.arguments | ranges::views::transform(argsTransform), ", "));
		else
			m_result << fmt::format("function {0}:\n {0}({1})", escape(_fun.name.str()), fmt::join(m_cfg.arguments | ranges::views::transform(argsTransform), ", "));
		m_result << "\"];\n";
		m_result << "FunctionEntry_" << escape(_fun.name.str()) << "_" << m_cfg.entry.value << " -> Block" << m_functionIndex << "_" << m_cfg.entry.value << ";\n";
		printBlock(m_cfg.entry);
	}

	SSACFG const& m_cfg;
	std::unique_ptr<TerminationPathAnalysis> m_cfgRevertPaths;
	size_t m_functionIndex;
	LivenessAnalysis const* m_liveness;
	SSACFGStackLayout const* m_stackLayout;
	std::stringstream m_result{};
};
}

std::string SSACFG::toDot(
	bool _includeDiGraphDefinition,
	std::optional<size_t> _functionIndex,
	LivenessAnalysis const* _liveness,
	SSACFGStackLayout const* _stackLayout
) const
{
	std::ostringstream output;
	if (_includeDiGraphDefinition)
		output << "digraph SSACFG {\nnodesep=0.7;\ngraph[fontname=\"DejaVu Sans\", rankdir=LR]\nnode[shape=box,fontname=\"DejaVu Sans\"];\n\n";
	if (function)
		output << SSACFGPrinter(*this, _functionIndex ? *_functionIndex : static_cast<size_t>(1), *function, _liveness, _stackLayout);
	else
		output << SSACFGPrinter(*this, entry, _liveness, _stackLayout);
	if (_includeDiGraphDefinition)
		output << "}\n";
	return output.str();
}

std::string SSACFG::valueDescription(ValueId const& _valueId) const
{
	return SSACFGPrinter::varToString(*this, _valueId);
}
