rule Bypass_Evasion_3 {
    meta:
        description = "Evasion bypass detection rules for VM sandbox"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? F7 83 C4 14 56 EB 8B EC EB }
        $pattern1 = { 8B CE EB 8B CE EB 2F FF }
        $pattern2 = { 8D 00 5E 5D EB 5A EA }

    condition:
        any of them
}