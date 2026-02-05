rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D6 ?? ?? ?? FF 15 B0 70 2D 01 59 50 E8 ?? ?? ?? ?? C9 5A }
        $pattern1 = { E8 E3 ?? ?? ?? ?? C1 E8 08 FF 75 0C FF D6 ?? ?? ?? ?? 59 }
        $pattern2 = { E8 E3 ?? ?? ?? ?? C1 E8 08 FF D6 ?? ?? ?? ?? C9 59 50 E8 }

    condition:
        any of them
}