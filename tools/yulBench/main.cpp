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

#include "libyul/backends/evm/SSACFGEVMCodeTransform.h"
#include "libyul/backends/evm/ssa/StackLayoutGenerator.h"


#include <libyul/YulStack.h>
#include <libyul/backends/evm/EVMDialect.h>
#include <libyul/backends/evm/ssa/SSACFG.h>

#include <liblangutil/ErrorReporter.h>

#include <benchmark/benchmark.h>

#include <filesystem>
#include <fstream>
#include <libyul/backends/evm/ssa/ControlFlow.h>
#include <libyul/backends/evm/ssa/SSACFGBuilder.h>

std::shared_ptr<solidity::yul::Object> parse(std::string_view _filePath)
{
	auto const fileContents = [&]
	{
		std::filesystem::path const file(_filePath);
		if (!std::filesystem::exists(file) || !std::filesystem::is_regular_file(file))
			throw std::runtime_error("File does not exist.");
		std::string result;
		if (std::ifstream is{file, std::ios::binary | std::ios::ate})
		{
			auto size = is.tellg();
			result = std::string(size, '\0');
			is.seekg(0);
			if (!is.read(&result[0], size))
				throw std::runtime_error("Failed to read file.");
		}
		else
			throw std::runtime_error("Failed to open file.");
		return result;
	}();
	solidity::yul::YulStack stack (
		solidity::langutil::EVMVersion::current(),
		std::nullopt,
		solidity::yul::Language::StrictAssembly,
		solidity::frontend::OptimiserSettings::standard(),
		solidity::langutil::DebugInfoSelection::None()
	);
	stack.parseAndAnalyze("", fileContents);
	return stack.parserResult();
}

std::unique_ptr<solidity::yul::ssa::ControlFlow> buildSSACFG(solidity::yul::Object const& _object)
{
	std::unique_ptr<solidity::yul::ssa::ControlFlow> controlFlow = solidity::yul::ssa::SSACFGBuilder::build(
		*_object.analysisInfo,
		*_object.dialect(),
		_object.code()->root(),
		false
	);
	return controlFlow;
}

solidity::yul::ssa::ControlFlowLiveness computeLiveness(solidity::yul::ssa::ControlFlow const& _controlFlow)
{
	return solidity::yul::ssa::ControlFlowLiveness(_controlFlow);
}

static void BM_BuildSSACFG(benchmark::State& state) {
	auto const& object = parse("/home/mho/dev/solidity/deposit.yul");
	for (auto _ : state) {
		auto cfg = buildSSACFG(*object);
		benchmark::DoNotOptimize(cfg);
	}
}

static void BM_SSACFGLiveness(benchmark::State& state) {
	auto const& object = parse("/home/mho/dev/solidity/deposit.yul");
	auto const cfg = buildSSACFG(*object);
	for (auto _ : state) {
		auto cfgLiveness = computeLiveness(*cfg);
		benchmark::DoNotOptimize(cfgLiveness);
	}
}

static void BM_SSACFGStackLayoutGenerator(benchmark::State& state) {
	auto const& object = parse("/home/mho/dev/solidity/deposit.yul");
	auto const cfg = buildSSACFG(*object);
	auto const cfgLiveness = computeLiveness(*cfg);
	for (auto _ : state) {
		std::vector<solidity::yul::ssa::SSACFGStackLayout> layouts;
		layouts.reserve(cfg->functionGraphs.size());

		for (size_t i = 0; i < cfg->functionGraphs.size(); i++)
		{
			solidity::yul::ssa::TerminationPathAnalysis t(*cfg->functionGraphs[i], cfgLiveness.cfgLiveness[i]->topologicalSort());
			layouts.push_back(solidity::yul::ssa::StackLayoutGenerator::generate(*cfgLiveness.cfgLiveness[i], t));
		}

		benchmark::DoNotOptimize(layouts);
	}
}

BENCHMARK(BM_BuildSSACFG);
BENCHMARK(BM_SSACFGLiveness);
BENCHMARK(BM_SSACFGStackLayoutGenerator);
BENCHMARK_MAIN();
