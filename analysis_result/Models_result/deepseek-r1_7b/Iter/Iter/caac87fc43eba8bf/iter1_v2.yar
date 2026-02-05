rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule targeting call execution analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FFFF 55 FF ?? ?? ?? }
        $pattern1 = { 6A 5A CE E8 FF FF ?? ?? ?? ?? }
        $pattern2 = { 74 0C FF 8B 45 ?? 83 C4 ?? }

    condition:
        any of them
}