rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting different parts of the exit process"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF 75 08 E8 C8 FF FF ?? }
        $pattern1 = { 6A ?? 5A 8B C4 FF 75 E8 C8 F0 ?? }
        $pattern2 = { 3A ?? FF 75 08 E8 C8 FF FF 55 C0 }

    condition:
        any_of them
}