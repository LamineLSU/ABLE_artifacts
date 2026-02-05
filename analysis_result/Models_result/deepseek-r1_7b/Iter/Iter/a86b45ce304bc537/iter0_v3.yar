rule Evasion_Bypass_Patterns
{
    meta:
        description = "Evasion bypass patterns for specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 45 ?? ?? ?? ?? E8 ?? }
        $pattern1 = { 6A 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { F8 7E 73 79 7E 79 FC 4F 00 8B FC }

    condition:
        any of them
}