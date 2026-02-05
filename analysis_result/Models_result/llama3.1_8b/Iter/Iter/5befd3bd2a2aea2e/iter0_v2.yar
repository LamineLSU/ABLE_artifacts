rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 8B EC FF 75 08 E8 C8 FF FF FF ?? ?? ?? ?? }

    condition:
        any of them
}