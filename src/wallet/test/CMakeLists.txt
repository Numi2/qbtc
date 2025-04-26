#   2023-present 
#    
#  .

# Do not use generator expressions in test sources because the
# SOURCES property is processed to gather test suite macros.
target_sources(test_bitcoin
  PRIVATE
    init_test_fixture.cpp
    wallet_test_fixture.cpp
    db_tests.cpp
    coinselector_tests.cpp
    feebumper_tests.cpp
    group_outputs_tests.cpp
    init_tests.cpp
    ismine_tests.cpp
    psbt_wallet_tests.cpp
    scriptpubkeyman_tests.cpp
    spend_tests.cpp
    wallet_crypto_tests.cpp
    wallet_tests.cpp
    wallet_transaction_tests.cpp
    walletdb_tests.cpp
    walletload_tests.cpp
    blockindex_qs_tests.cpp
    serialization_qs_tests.cpp
    hash_qs_tests.cpp
    net_qs_tests.cpp
    pqckeys_tests.cpp
    crypto_tests.cpp
)
target_link_libraries(test_bitcoin
    bitcoin_wallet
    bitcoin_node
    bitcoin_crypto
    bitcoin_common
)
