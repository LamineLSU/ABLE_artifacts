rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? C8 FF FF FF CA 00 40 E7 C3 }

    condition:
        any of them
}