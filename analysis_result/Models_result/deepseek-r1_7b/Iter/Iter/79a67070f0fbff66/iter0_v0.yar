rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 C4 89 45 C4 73 22 EB CD }
        $pattern1 = { FF 15 F0 50 61 00 8B 55 C4 8B 45 E0 EB CD }
        $pattern2 = { FF 15 F0 50 61 00 8B 45 E0 EB CD }

    condition:
        any of them
}