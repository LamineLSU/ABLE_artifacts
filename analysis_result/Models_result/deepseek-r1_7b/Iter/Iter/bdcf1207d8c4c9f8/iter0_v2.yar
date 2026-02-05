rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B FF ?? 55 ?? E8 C8 FF FF FF }
        $pattern1 = { 55 ?? FF 75 08 ?? ?? E8 C8 FF FF FF }
        $pattern2 = { 8B FF 55 FF 75 08 ?? ?? FF 15 AC B0 41 00 }

    condition:
        any()
}