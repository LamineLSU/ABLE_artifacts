rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass using conditional jumps and stack manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 41 A0 5D FF D2 45 ?C 00 00 ?F ?F }
        $pattern1 = { FF D8 41 A0 63 00 00 00 00 00 00 00 00 }
        $pattern2 = { 22 AB 38 0C 6B 6D EC 99 00 00 FF 00 }
    condition:
        any of them
}