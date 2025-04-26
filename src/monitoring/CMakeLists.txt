# Monitoring components for QuBitcoin

set(MONITORING_HEADERS
  metrics.h
  collectors.h
)

set(MONITORING_SOURCES
  metrics.cpp
  collectors.cpp
)

add_library(qubitcoin_monitoring
  ${MONITORING_HEADERS}
  ${MONITORING_SOURCES}
)

target_include_directories(qubitcoin_monitoring
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${QUBITCOIN_INCLUDES}
)

target_link_libraries(qubitcoin_monitoring
  qubitcoin_common
  qubitcoin_consensus
  qubitcoin_crypto
  qubitcoin_util
)

# Install prometheus alert rules
install(FILES
  alert_rules.yml
  DESTINATION ${CMAKE_INSTALL_DATADIR}/qubitcoin/monitoring
) 