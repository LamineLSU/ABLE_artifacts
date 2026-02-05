rule Bypass_Sample_1 {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 85 C0 74 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any of them
}