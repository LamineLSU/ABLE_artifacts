rule Bypass_Sample_Evolved {
    meta:
        description = "Evasion bypass rule - targeting conditionally checked API exits"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 EC 5F 9C 76 04 00 00 }
        $pattern1 = { 8B DD FF 00 00 00 00 00 }
        $pattern2 = { 8B 4D 04 00 00 00 00 00 }

    condition:
        any of them
}