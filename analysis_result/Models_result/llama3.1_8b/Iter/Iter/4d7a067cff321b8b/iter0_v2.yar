rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? FF FF FF ?? ?? ?? 85 C0 }
        $pattern1 = { FF 75 ?? FF ?? ?? AC B0 41 00 ?? ?? ?? ?? }
        $pattern2 = { 8B FF 55 8B EC FF 75 ?? ?? E8 ?? FF FF FF ?? ?? ?? }

    condition:
        any of them
}