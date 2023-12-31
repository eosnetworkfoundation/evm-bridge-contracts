#include <boost/test/included/unit_test.hpp>
#include <boost/test/unit_test.hpp>
#include <cstdlib>
#include <eosio/chain/contract_table_objects.hpp>
#include <eosio/chain/exceptions.hpp>
#include <eosio/chain/global_property_object.hpp>
#include <eosio/chain/resource_limits.hpp>
#include <eosio/chain/wast_to_wasm.hpp>
#include <fc/log/logger.hpp>
#include <iostream>

#define BOOST_TEST_STATIC_LINK

void translate_fc_exception(const fc::exception& e) {
    std::cerr << "\033[33m" << e.to_detail_string() << "\033[0m" << std::endl;
    // BOOST_TEST_FAIL("Caught Unexpected Exception");
    throw std::runtime_error("Caught Unexpected Exception");
}

boost::unit_test::test_suite* init_unit_test_suite(int argc, char* argv[]) {
    // Turn off blockchain logging if no --verbose parameter is not added
    // To have verbose enabled, call "tests/chain_test -- --verbose"
    bool is_verbose = false;
    std::string verbose_arg = "--verbose";
    for (int i = 0; i < argc; i++) {
        if (verbose_arg == argv[i]) {
            is_verbose = true;
            break;
        }
    }
    if (!is_verbose)
        fc::logger::get(DEFAULT_LOGGER).set_log_level(fc::log_level::error);
    else
        fc::logger::get(DEFAULT_LOGGER).set_log_level(fc::log_level::debug);

    // Register fc::exception translator
    boost::unit_test::unit_test_monitor.template register_exception_translator<fc::exception>(&translate_fc_exception);
    auto seed = time(NULL);
    std::srand(seed);
    std::cout << "Random number generator seeded to " << seed << std::endl;
    return nullptr;
}
