rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass patterns targeting EDAPP calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 59 C7 ?? ?? 3E 06 F4 }
        $pattern1 = { E8 ?? A2 F7 8F 4D 8C E8 ?? ?? }
        $pattern2 = { E8 ?? FF 7C 3A 8B 5A }

    condition:
        any of them
}