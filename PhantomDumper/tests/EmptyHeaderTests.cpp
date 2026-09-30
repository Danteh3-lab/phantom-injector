#include "empty.hpp"
#include <iostream>
static_assert(phantom_dump::schema_version == 1 && phantom_dump::game_name == "empty-game");
static_assert(phantom_dump::modules.empty() && phantom_dump::fields.empty());
static_assert(phantom_dump::capture_id.empty() && phantom_dump::created_at_utc.empty());
int main() { std::cout << "Empty generated C++17 header checks passed\n"; }
