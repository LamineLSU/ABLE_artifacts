rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 20 EB CD 51 FF 15 F0 50 61 00 }
        $pattern1 = { 20 FF EE CE 52 E8 8D 9A FF FF C7 45 C4 00 00 00 00 }
        $pattern2 = { 20 FF EE CE 8B 55 C4 8B 45 E4 8B 0C 90 }

    condition:
        any of them
}