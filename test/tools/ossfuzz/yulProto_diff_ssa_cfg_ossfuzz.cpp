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

#include <fstream>

#include <boost/version.hpp>
#if (BOOST_VERSION < 108800)
#include <boost/process.hpp>
#else
#define BOOST_PROCESS_VERSION 1
#include <boost/process/v1/search_path.hpp>
#endif
#include <boost/filesystem.hpp>

#include <test/tools/ossfuzz/yulProto.pb.h>
#include <test/tools/ossfuzz/protoToYul.h>
#include <test/libyul/YulOptimizerTestCommon.h>

#include <src/libfuzzer/libfuzzer_macro.h>

#include <libyul/YulStack.h>
#include <libyul/Exceptions.h>

#include <liblangutil/DebugInfoSelection.h>
#include <liblangutil/EVMVersion.h>
#include <liblangutil/SourceReferenceFormatter.h>

using namespace solidity::util;
using namespace solidity::langutil;
using namespace solidity::yul;
using namespace solidity::yul::test;
using namespace solidity::yul::test::yul_fuzzer;

bool checkEquivalenceHEVM(
	std::string const& bytecode1,
	std::string const& bytecode2,
	std::string const& yulSource)
{
	namespace fs = boost::filesystem;

	auto writeTempFile = [](std::string const& bytecode, std::string const& prefix) -> std::string {
		std::string filename = (fs::temp_directory_path() / fs::unique_path(prefix + "-%%%%%%%%.bin")).string();
		std::ofstream f(filename);
		if (!f)
			throw std::runtime_error("Failed to create temporary file: " + filename);
		f << bytecode;
		return filename;
	};

	std::string fileA = writeTempFile(bytecode1, "bytecode-a");
	std::string fileB = writeTempFile(bytecode2, "bytecode-b");

	boost::process::ipstream outStream, errStream;

	std::vector<std::string> args = {
		"equivalence",
		"--code-a-file", fileA,
		"--code-b-file", fileB,
		"--smttimeout", "1",
		"--num-solvers", "1",
		"--only-deployed"
	};

	auto hevmPath = boost::process::search_path("hevm");
	if (hevmPath.empty())
		throw std::runtime_error("HEVM not found in PATH.");

	boost::process::child hevmProcess(
		hevmPath,
		boost::process::args(args),
		boost::process::std_out > outStream,
		boost::process::std_err > errStream);

	std::ostringstream outBuffer, errBuffer;
	auto readStream = [](boost::process::ipstream& stream, std::ostringstream& buffer) {
		std::string line;
		while (std::getline(stream, line))
			buffer << line << '\n';
	};

	std::thread outThread(readStream, std::ref(outStream), std::ref(outBuffer));
	std::thread errThread(readStream, std::ref(errStream), std::ref(errBuffer));

	hevmProcess.wait();
	outThread.join();
	errThread.join();

	bool success = (hevmProcess.exit_code() == 0);
	if (!success)
	{
		std::cout << "=== HEVM EQUIVALENCE CHECK FAILED ===" << std::endl;
		std::cout << "Yul Source Input:\n" << yulSource << std::endl;
		std::cout << "Bytecode length (Via-IR): " << bytecode1.length() << std::endl;
		std::cout << "Bytecode length (SSA CFG): " << bytecode2.length() << std::endl;
		std::cout << "HEVM output:\n" << outBuffer.str() << std::endl;
		// FIXME: Hevm does not output to stderr in case of a mismatch, it outputs to stdout.
		//std::cerr << "HEVM error:\n" << errBuffer.str() << std::endl;
		std::cerr << "Bytecode files kept for analysis:\n  Via-IR: " << fileA << "\n  SSA CFG: " << fileB << std::endl;
	}
	else
	{
		fs::remove(fileA);
		fs::remove(fileB);
	}

	return success;
}


DEFINE_PROTO_FUZZER(Program const& _input)
{
	ProtoConverter converter;
	std::string yul_source = converter.programToString(_input);
	EVMVersion version = converter.version();

	if (const char* dump_path = getenv("PROTO_FUZZER_DUMP_PATH"))
	{
		std::ofstream of(dump_path);
		of.write(yul_source.data(), static_cast<std::streamsize>(yul_source.size()));
	}

	YulStringRepository::reset();

	auto createParsedStack = [&]() -> YulStack {
		YulStack stack(
			version,
			std::nullopt,
			YulStack::Language::StrictAssembly,
			solidity::frontend::OptimiserSettings::full(),
			DebugInfoSelection::AllExceptExperimental()
		);

		if (
			!stack.parseAndAnalyze("source", yul_source) ||
			!stack.parserResult()->hasCode() ||
			!stack.parserResult()->analysisInfo ||
			Error::containsErrors(stack.errors())
		)
		{
			SourceReferenceFormatter{std::cout, stack, false, false}.printErrorInformation(stack.errors());
			yulAssert(false, "Proto fuzzer generated malformed program");
		}
		stack.optimize();
		return stack;
	};

	auto assemble = [&](bool _ssaCfgCodegen) -> std::pair<MachineAssemblyObject, MachineAssemblyObject> {
		YulStack stack = createParsedStack();
		MachineAssemblyObject evmAsm, runtimeAsm;
		std::tie(evmAsm, runtimeAsm) = stack.assembleWithDeployed({}, _ssaCfgCodegen);
		return std::make_pair(std::move(evmAsm), std::move(runtimeAsm));
	};

	try
	{
		auto [evmAsm1, runtimeAsm1] = assemble(false); // Via-IR codegen
		auto [evmAsm2, runtimeAsm2] = assemble(true);  // SSA CFG codegen

		auto checkEquivalence = [&](
			std::string const& _kind,
			auto const& _bytecode1,
			auto const& _bytecode2
		) {
			if (_bytecode1 && _bytecode2)
			{
				std::string hex1 = _bytecode1->toHex();
				std::string hex2 = _bytecode2->toHex();

				if (hex1 == hex2)
					return;

				// If the bytecode differs, check equivalence using HEVM
				if (!checkEquivalenceHEVM(hex1, hex2, yul_source))
					throw std::runtime_error(_kind + " bytecode differs:\n"
						"Via IR: " + hex1 + "\n"
						"SSA CFG: " + hex2);
			}
		};

		checkEquivalence("Object", evmAsm1.bytecode, evmAsm2.bytecode);
		checkEquivalence("Runtime Object", runtimeAsm1.bytecode, runtimeAsm2.bytecode);
	}
	catch (std::runtime_error const& e)
	{
		std::cout << "Error: " << e.what() << std::endl;
		std::cout << "EVM Version: " << version.name() << std::endl;
		yulAssert(false, "Bytecode differ between SSA CFG and IR codegen.");
	}

	return;
}
