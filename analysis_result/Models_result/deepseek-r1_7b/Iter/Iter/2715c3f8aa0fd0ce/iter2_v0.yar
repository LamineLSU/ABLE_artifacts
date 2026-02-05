rule Bypass_Evasion {
    meta:
        description = "Bypass rules targeting E8F72500 calls in disassembled code"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F7 25 00 ?? 30 83 F8 74 20 }
        $pattern1 = { E8 F7 25 00 ?? 6C 8B 45 ?? }
        $pattern2 = { E8 F7 25 00 ?? FC 8B 45 ?? }

    condition:
        any of them
}