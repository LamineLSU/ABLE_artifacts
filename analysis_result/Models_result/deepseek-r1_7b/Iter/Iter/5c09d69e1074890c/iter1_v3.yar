rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 55 14 ?? ?? ?? ?? ?? ?? }
        $pattern1 = { 83 C4 14 ?? EA ?? ?? }
        $pattern2 = { E8 74 0A 00 00 ?? ?? CA ?? ?? }

    condition:
        any of them
}