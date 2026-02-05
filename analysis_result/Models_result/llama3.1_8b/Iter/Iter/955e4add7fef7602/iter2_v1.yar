rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C3 85 DB ?? ?? ?? ?? FF D0 }
        $pattern1 = { 83 EC 08 E8 C8 ?? ?? ?? ?? F9 }
        $pattern2 = { 89 F4 57 FF D6 8A 44 24 04 }

    condition:
        any of them
}