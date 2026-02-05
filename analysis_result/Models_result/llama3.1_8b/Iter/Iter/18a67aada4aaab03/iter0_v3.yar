rule Bypass_Sample_1 {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 83 F8 01 74 20 64 A1 30 00 00 00 8B 40 68 C1 E8 80 A0 01 }

    condition:
        any of them
}