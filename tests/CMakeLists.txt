# The whole suite is one binary: the cases are fast, and a single executable
# means `ctest` failures and a direct `./policy-tests --filter X` run give
# identical output.
add_executable(policy-tests
  test_main.cpp
  test_wire.cpp
  test_imsi.cpp
  test_yaml.cpp
  test_rules.cpp
  test_store.cpp
  test_engine.cpp
  test_hdr.cpp
  test_rcu.cpp
  test_golden.cpp
  test_reload_concurrency.cpp
  test_admin_http.cpp)

target_include_directories(policy-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(policy-tests PRIVATE policy_net)

# Tests that read config/rules.yaml and the golden corpus use repository-root
# relative paths, so the working directory is fixed here rather than left to
# whoever invokes ctest.
add_test(NAME policy-tests COMMAND policy-tests
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# Named subsets, so a failure in CI points at an area rather than at "tests".
foreach(suite Wire Imsi Yaml Rules Store Engine EngineProperty Hdr Rcu Golden
              ReloadConcurrency AdminHttp)
  add_test(NAME suite.${suite}
           COMMAND policy-tests --filter ${suite}.
           WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endforeach()

set_tests_properties(policy-tests PROPERTIES TIMEOUT 300)
