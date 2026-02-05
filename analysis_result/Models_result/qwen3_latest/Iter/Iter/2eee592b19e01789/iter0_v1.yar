rule TestALandJE {
    meta:
        description = "Matches the test al, al followed by je instruction sequence"
    condition:
        84 C0 74 11
}

rule CallTerminateProcess {
    meta:
        description = "Matches the call to TerminateProcess function"
    condition:
        FF 15 1E 17 01 00
}

rule CallExitProcess {
    meta:
        description = "Matches the call to ExitProcess function"
    condition:
        FF 15 3F 18 01 00
}