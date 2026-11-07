package tests.sdls_test

import data.sdls.anti_replay
import data.sdls.channel_binding
import data.sdls.frame_format
import data.sdls.sa_structure
import data.tests.fixtures as fx
import rego.v1

# --- baseline ---------------------------------------------------------------

test_baseline_has_no_sdls_findings if {
	count(sa_structure.deny) == 0 with input as fx.base
	count(channel_binding.deny) == 0 with input as fx.base
	count(anti_replay.deny) == 0 with input as fx.base
	count(anti_replay.warn) == 0 with input as fx.base
	count(frame_format.deny) == 0 with input as fx.base
}

# --- SDLS-001..005: SA structure -------------------------------------------

test_sdls_001_rejects_unknown_service if {
	fx.ids(sa_structure.deny) == {"SDLS-001"} with input as fx.with_tc({"service": "integrity"})
}

test_sdls_001_rejects_missing_service if {
	"SDLS-001" in fx.ids(sa_structure.deny) with input as fx.db([object.remove(fx.tc_ae, ["service"])])
}

test_sdls_002_rejects_missing_mandatory_parameter if {
	fx.ids(sa_structure.deny) == {"SDLS-002"} with input as fx.db([object.remove(fx.tc_ae, ["pad_length_octets"]), fx.tm_auth])
}

test_sdls_003_rejects_spi_zero if {
	fx.ids(sa_structure.deny) == {"SDLS-003"} with input as fx.with_tc({"spi": 0})
}

test_sdls_003_rejects_spi_65535 if {
	fx.ids(sa_structure.deny) == {"SDLS-003"} with input as fx.with_tc({"spi": 65535})
}

test_sdls_003_accepts_range_edges if {
	count(sa_structure.deny) == 0 with input as fx.with_tc({"spi": 65534})
}

test_sdls_004_rejects_duplicate_spi_same_protocol if {
	fx.ids(sa_structure.deny) == {"SDLS-004"} with input as fx.with_enc({"spi": 10})
}

test_sdls_004_allows_same_spi_on_different_protocol if {
	count(sa_structure.deny) == 0 with input as fx.with_tm({"spi": 1})
}

test_sdls_005_rejects_sa_without_channels if {
	fx.ids(sa_structure.deny) == {"SDLS-005"} with input as fx.with_tc({"gvcids": []})
}

# --- SDLS-010..013: channel binding ----------------------------------------

test_sdls_010_rejects_two_sas_on_one_vc if {
	"SDLS-010" in fx.ids(channel_binding.deny) with input as fx.with_enc({"gvcids": [{"tfvn": 0, "scid": 1, "vcid": 0}]})
}

test_sdls_011_rejects_sa_on_idle_vc if {
	fx.ids(channel_binding.deny) == {"SDLS-011"} with input as fx.with_enc({"gvcids": [{"tfvn": 0, "scid": 1, "vcid": 7}]})
}

test_sdls_012_rejects_multi_vc_sa_with_cop if {
	two_vcs := [{"tfvn": 0, "scid": 1, "vcid": 0}, {"tfvn": 0, "scid": 1, "vcid": 1}]
	tc_vc1 := object.union(fx.tc_vc, {"name": "tc1", "gvcid": {"tfvn": 0, "scid": 1, "vcid": 1}})
	db := object.union(fx.with_tc({"gvcids": two_vcs}), {"virtual_channels": array.concat(fx.vcs, [tc_vc1])})
	fx.ids(channel_binding.deny) == {"SDLS-012"} with input as db
}

test_sdls_012_allows_multi_vc_sa_without_cop if {
	two_vcs := [{"tfvn": 0, "scid": 1, "vcid": 2}, {"tfvn": 0, "scid": 1, "vcid": 3}]
	payload2 := object.union(fx.payload_vc, {"name": "payload2", "gvcid": {"tfvn": 0, "scid": 1, "vcid": 3}})
	db := object.union(fx.with_enc({"gvcids": two_vcs}), {"virtual_channels": array.concat(fx.vcs, [payload2])})
	count(channel_binding.deny) == 0 with input as db
}

test_sdls_013_rejects_undeclared_vc if {
	fx.ids(channel_binding.deny) == {"SDLS-013"} with input as fx.with_enc({"gvcids": [{"tfvn": 0, "scid": 1, "vcid": 5}]})
}

# --- SDLS-020..022: anti-replay --------------------------------------------

test_sdls_020_rejects_authenticated_sa_without_sequence_number if {
	"SDLS-020" in fx.ids(anti_replay.deny) with input as fx.with_tc({"sequence_number": {"length_octets": 0, "window": 5}})
}

test_sdls_020_rejects_oversized_sequence_number if {
	fx.ids(anti_replay.deny) == {"SDLS-020"} with input as fx.with_tm({"sequence_number": {"length_octets": 9, "window": 5}})
}

test_sdls_020_ignores_encryption_only_sa if {
	count(anti_replay.deny) == 0 with input as fx.base
}

test_sdls_021_rejects_zero_window if {
	fx.ids(anti_replay.deny) == {"SDLS-021"} with input as fx.with_tc({"sequence_number": {"length_octets": 4, "window": 0}})
}

test_sdls_022_warns_on_wide_tc_window if {
	fx.ids(anti_replay.warn) == {"SDLS-022"} with input as fx.with_tc({"sequence_number": {"length_octets": 4, "window": 1000}})
	count(anti_replay.deny) == 0 with input as fx.with_tc({"sequence_number": {"length_octets": 4, "window": 1000}})
}

test_sdls_022_respects_mission_profile_override if {
	count(anti_replay.warn) == 0 with input as fx.with_tc({"sequence_number": {"length_octets": 4, "window": 1000}})
		with data.mission_profile.max_tc_window as 2048
}

test_sdls_022_does_not_apply_to_telemetry if {
	count(anti_replay.warn) == 0 with input as fx.with_tm({"sequence_number": {"length_octets": 4, "window": 1000}})
}

# --- SDLS-030..032: frame format -------------------------------------------

test_sdls_030_rejects_encrypting_sa_without_iv if {
	fx.ids(frame_format.deny) == {"SDLS-030"} with input as fx.with_enc({"iv_length_octets": 0})
}

test_sdls_030_rejects_iv_over_32_octets if {
	fx.ids(frame_format.deny) == {"SDLS-030"} with input as fx.with_enc({"iv_length_octets": 33})
}

test_sdls_031_rejects_authenticating_sa_without_mac if {
	fx.ids(frame_format.deny) == {"SDLS-031"} with input as fx.with_tm({"mac_length_octets": 0})
}

test_sdls_031_rejects_mac_on_encryption_only_sa if {
	fx.ids(frame_format.deny) == {"SDLS-031"} with input as fx.with_enc({"mac_length_octets": 16})
}

test_sdls_032_rejects_oversized_security_header if {
	# 2 (SPI) + 32 (IV) + 8 (SN) + 2 (pad) = 44: fine
	count(frame_format.deny) == 0 with input as fx.with_tc({"iv_length_octets": 32, "sequence_number": {"length_octets": 8, "window": 5}, "pad_length_octets": 2})

	# 2 + 32 + 8 + 30 = 72: too large
	"SDLS-032" in fx.ids(frame_format.deny) with input as fx.with_tc({"iv_length_octets": 32, "sequence_number": {"length_octets": 8, "window": 5}, "pad_length_octets": 30})
}

test_sdls_006_rejects_proximity1 if {
	fx.ids(sa_structure.deny) == {"SDLS-006"} with input as fx.with_tc({"protocol": "Proximity-1"})
}

test_sdls_006_rejects_missing_protocol if {
	fx.ids(sa_structure.deny) == {"SDLS-006"} with input as fx.db([object.remove(fx.tc_ae, ["protocol"]), fx.tm_auth, fx.tm_enc])
}
