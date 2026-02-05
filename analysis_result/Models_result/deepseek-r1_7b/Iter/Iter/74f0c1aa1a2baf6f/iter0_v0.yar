rule Bypass_Evasion_3 {
    meta:
        description = "Evasion bypass rules targeting specific function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5A 85 C0 7E ?? }
        $pattern1 = { FF 05 F9 A4 68 6B 85 C0 7E ?? }
        $pattern2 = { 68 68 3A 85 C0 7E ?? FF 15 F9 A4 7E ?? }

    condition:
        any of them
}