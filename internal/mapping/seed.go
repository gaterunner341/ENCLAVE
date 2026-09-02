package mapping

// Seed tables ship with the binary so that a first import produces control
// evidence rather than a page of "unmapped". They are deliberately small and
// each one is visible and removable on the Mappings page.
//
// The CCI table is a starter subset covering the identifiers that appear most
// often in operating system and network device STIGs. It is not the
// authoritative list. Importing DISA's U_CCI_List.xml on the Mappings page
// replaces it with the full one, and doing so is the documented first step for
// anyone using STIG results seriously.

func seedSets() []*Set {
	return []*Set{
		{
			ID: "seed-cci-800-53r5", Name: "CCI to NIST SP 800-53 Rev 5 (starter subset)",
			Scheme: SchemeCCI, Target: "nist-800-53r5", BuiltIn: true,
			Source: "Shipped with ENCLAVE",
			Note: "A subset of the DISA CCI list covering the identifiers common to operating system and network STIGs. " +
				"Import U_CCI_List.xml to replace it with the authoritative mapping.",
			Entries: expand(map[string]string{
				"CCI-000015": "AC-2(1)", "CCI-000017": "AC-2(3)", "CCI-000018": "AC-2(4)",
				"CCI-000019": "AC-2(4)", "CCI-000020": "AC-2(4)", "CCI-000044": "AC-7",
				"CCI-000048": "AC-8", "CCI-000050": "AC-8", "CCI-000054": "AC-10",
				"CCI-000056": "AC-11", "CCI-000057": "AC-11", "CCI-000058": "AC-11",
				"CCI-000060": "AC-11(1)", "CCI-000061": "AC-11(1)", "CCI-000067": "AC-17(1)",
				"CCI-000068": "AC-17(2)", "CCI-000130": "AU-3", "CCI-000131": "AU-3",
				"CCI-000132": "AU-3", "CCI-000133": "AU-3", "CCI-000134": "AU-3",
				"CCI-000135": "AU-3(1)", "CCI-000138": "AU-4", "CCI-000139": "AU-5",
				"CCI-000140": "AU-5", "CCI-000143": "AU-5(1)", "CCI-000144": "AU-5(2)",
				"CCI-000148": "AU-6", "CCI-000154": "AU-6(3)", "CCI-000158": "AU-7(1)",
				"CCI-000159": "AU-8", "CCI-000162": "AU-9", "CCI-000163": "AU-9",
				"CCI-000164": "AU-9", "CCI-000166": "AU-10", "CCI-000167": "AU-9(4)",
				"CCI-000169": "AU-12", "CCI-000171": "AU-12", "CCI-000172": "AU-12",
				"CCI-000185": "IA-5(2)", "CCI-000186": "IA-5(2)", "CCI-000187": "IA-5",
				"CCI-000192": "IA-5(1)", "CCI-000193": "IA-5(1)", "CCI-000194": "IA-5(1)",
				"CCI-000195": "IA-5(1)", "CCI-000196": "IA-5(1)", "CCI-000197": "IA-5(1)",
				"CCI-000198": "IA-5(1)", "CCI-000199": "IA-5(1)", "CCI-000200": "IA-5(1)",
				"CCI-000205": "IA-5(1)", "CCI-000206": "IA-6", "CCI-000213": "AC-3",
				"CCI-000225": "AC-6", "CCI-000345": "AC-17(3)", "CCI-000366": "CM-6",
				"CCI-000381": "CM-7", "CCI-000382": "CM-7", "CCI-000764": "IA-2",
				"CCI-000765": "IA-2(1)", "CCI-000766": "IA-2(2)", "CCI-000767": "IA-2(1)",
				"CCI-000768": "IA-2(2)", "CCI-000770": "IA-2(5)", "CCI-000772": "IA-3",
				"CCI-000778": "IA-3", "CCI-000795": "IA-4", "CCI-000803": "IA-7",
				"CCI-000877": "MA-4", "CCI-000879": "MA-4", "CCI-001090": "SC-4",
				"CCI-001095": "SC-5", "CCI-001133": "SC-10", "CCI-001184": "SC-23",
				"CCI-001188": "SC-23", "CCI-001199": "SC-28", "CCI-001233": "SI-2(2)",
				"CCI-001227": "SI-4", "CCI-001240": "SI-3", "CCI-001241": "SI-4",
				"CCI-001242": "SI-3", "CCI-001243": "SI-4", "CCI-001310": "SI-10",
				"CCI-001312": "SI-11", "CCI-001314": "SI-11", "CCI-001348": "AU-9(2)",
				"CCI-001350": "AU-9(3)", "CCI-001351": "AU-5(1)", "CCI-001368": "AC-4",
				"CCI-001384": "AC-8", "CCI-001385": "AC-8", "CCI-001386": "AC-8",
				"CCI-001387": "AC-8", "CCI-001388": "AC-8", "CCI-001403": "AC-2(4)",
				"CCI-001404": "AC-2(4)", "CCI-001405": "AC-2(4)", "CCI-001414": "AC-4",
				"CCI-001453": "AC-17(2)", "CCI-001499": "CM-5", "CCI-001682": "AC-2(2)",
				"CCI-001744": "CM-3(5)", "CCI-001749": "CM-14", "CCI-001762": "CM-7(1)",
				"CCI-001764": "CM-7(2)", "CCI-001774": "CM-7(5)", "CCI-001812": "CM-11",
				"CCI-001813": "CM-5", "CCI-001814": "CM-5", "CCI-001849": "AU-4",
				"CCI-001851": "AU-4", "CCI-001889": "AU-8", "CCI-001890": "AU-8",
				"CCI-001891": "AU-8", "CCI-001941": "IA-2(8)", "CCI-001942": "IA-2(8)",
				"CCI-001947": "MA-4", "CCI-001948": "MA-4", "CCI-002007": "IA-5(13)",
				"CCI-002038": "IA-11", "CCI-002039": "IA-11", "CCI-002041": "IA-5(1)",
				"CCI-002130": "AC-2(4)", "CCI-002132": "AC-2(4)", "CCI-002165": "AC-3",
				"CCI-002234": "AC-6(9)", "CCI-002235": "AC-6(10)", "CCI-002238": "AC-7",
				"CCI-002314": "AC-17(1)", "CCI-002322": "AC-17(9)", "CCI-002361": "AC-12",
				"CCI-002385": "SC-5", "CCI-002418": "SC-8", "CCI-002420": "SC-8(2)",
				"CCI-002421": "SC-8(1)", "CCI-002422": "SC-8(2)", "CCI-002450": "SC-13",
				"CCI-002475": "SC-28(1)", "CCI-002476": "SC-28(1)", "CCI-002605": "SI-2",
				"CCI-002696": "SI-6", "CCI-002699": "SI-6", "CCI-002702": "SI-6",
				"CCI-003123": "MA-4", "CCI-002890": "MA-4", "CCI-001958": "IA-3",
			}),
		},
		{
			ID: "seed-vuln-800-53r5", Name: "Unpatched vulnerabilities to NIST SP 800-53 Rev 5",
			Scheme: SchemeCVE, Target: "nist-800-53r5", BuiltIn: true,
			Source: "Shipped with ENCLAVE",
			Note: "Any finding that names a CVE is treated as evidence about flaw remediation and " +
				"vulnerability monitoring. The * key matches every CVE.",
			Entries: map[string][]string{"*": {"SI-2", "RA-5"}},
		},
		{
			ID: "seed-vuln-cis-v8", Name: "Unpatched vulnerabilities to CIS Controls v8",
			Scheme: SchemeCVE, Target: "cis-controls-v8", BuiltIn: true,
			Source:  "Shipped with ENCLAVE",
			Note:    "Any finding that names a CVE is treated as evidence about the vulnerability management safeguards.",
			Entries: map[string][]string{"*": {"7.2", "7.7"}},
		},
		{
			ID: "seed-vuln-csf-2", Name: "Unpatched vulnerabilities to NIST CSF 2.0",
			Scheme: SchemeCVE, Target: "nist-csf-2.0", BuiltIn: true,
			Source:  "Shipped with ENCLAVE",
			Note:    "Any finding that names a CVE is treated as evidence about the vulnerability and software maintenance outcomes.",
			Entries: map[string][]string{"*": {"ID.RA-01", "ID.RA-06", "PR.PS-02"}},
		},
	}
}

func expand(in map[string]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[normKey(k)] = []string{v}
	}
	return out
}
