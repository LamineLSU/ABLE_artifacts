rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 8B EC E8 ?? }
        $pattern1 = { 6A 5B 8B EC E8 74 07 }
        $pattern2 = { FF 75 08 FF 15 AC B0 41 00 }
    condition:
        any of them
}