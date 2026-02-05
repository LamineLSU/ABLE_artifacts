rule Bypass_Sample_Evolved {
    meta:
        description = "Evasion bypass rule - refined specific patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 08 C8 FF C8 FF 04 10 00 }
        $pattern1 = { 75 08 9C 5A 08 C8 FF C8 FF 04 10 }
        $pattern2 = { E8 25 ?? ?? ?? FF C8 FF 04 10 }

    condition:
        any of them
}