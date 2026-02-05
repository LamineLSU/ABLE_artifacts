rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF ?? ?? ?? ?? 55 8B EC }
        $pattern1 = { E8 E4 32 00 00 ?? ?? ?? ?? 83 F8 01 }
        $pattern2 = { 64 A1 30 00 00 00 ?? ?? ?? ?? A8 01 }

    condition:
        any of them
}