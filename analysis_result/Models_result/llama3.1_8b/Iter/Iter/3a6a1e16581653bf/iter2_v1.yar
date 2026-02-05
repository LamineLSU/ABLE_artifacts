rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? ?? ?? ?? }
        $pattern1 = { 6A 5B 5A 8B CE E8 25 50 00 00 }
        $pattern2 = { 03 C3 BA 04 01 00 00 }

    condition:
        any of them
}