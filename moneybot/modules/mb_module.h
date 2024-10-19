#pragma once

#include <vector>

namespace moneybot
{
	struct export_symbol
	{
		size_t ordinal;
		uintptr_t address;
		const char* name;
	};
	struct module
	{
		const char* name;
		uintptr_t address;
		size_t    size;
		std::vector<export_symbol> export_symbols;
	};
}
