rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }
        $pattern1 = { C1 E8 08 A8 01 75 10 }
        $pattern2 = { FF 15 A0 F1 42 00 }

    condition:
        all of them
}