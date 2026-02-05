rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? FF 15 ?? ?? ?? CA 11 50 }
        $pattern1 = { 8B FF 55 8B EC FF 75 08 E8 ?? ?? ?? ?? CA }
        $pattern2 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 ?? ?? A8 01 FF 15 ?? ?? CE 11 50 }

    condition:
        any of them
}