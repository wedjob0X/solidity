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

#include <libyul/backends/evm/AbstractAssembly.h>
#include <libyul/backends/evm/ssa/SSACFG.h>
#include <libyul/backends/evm/ssa/Stack.h>

#include <libyul/Exceptions.h>

#include <range/v3/view/reverse.hpp>

#include <map>
#include <range/v3/algorithm/count_if.hpp>
#include <variant>
#include <vector>

namespace solidity::yul::ssa
{

struct SSACFGStackLayout
{
	// Each block has its own layout
	struct BlockLayout
	{
		// stack layout required to enter the block
		StackData stackIn;
		// stack layout required to execute the i-th operation in the block
		std::vector<StackData> operationIn;
		// stack after the block was executed
		StackData stackOut;
	};

	// each block has a fixed list of operations
	using BlockLayouts = std::vector<BlockLayout>;

	BlockLayout& operator[](SSACFG::BlockId const _blockId)
	{
		yulAssert(_blockId.value < blockLayouts.size());
		return blockLayouts[_blockId.value];
	}

	BlockLayout const& operator[](SSACFG::BlockId const _blockId) const
	{
		yulAssert(_blockId.value < blockLayouts.size());
		return blockLayouts[_blockId.value];
	}

	CallSites callSites;
	BlockLayouts blockLayouts;
};

struct ControlFlowLayout
{
	SSACFGStackLayout mainLayout;
	std::vector<SSACFGStackLayout> functionLayouts;
};
}
