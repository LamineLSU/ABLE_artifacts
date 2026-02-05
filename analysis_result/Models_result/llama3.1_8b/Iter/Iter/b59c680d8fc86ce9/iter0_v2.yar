rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { FF 15 A0 F1 42 00 8B EC E8 ?? ?? ?? ?? 83 F8 01 }
        $pattern1 = { 64 A1 30 00 00 00 B9 01 00 00 00 E8 ?? ?? ?? ?? }

    condition:
        any of them
}