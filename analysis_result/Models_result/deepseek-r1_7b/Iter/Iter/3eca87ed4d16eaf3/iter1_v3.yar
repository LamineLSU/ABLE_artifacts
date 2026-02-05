rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with early checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B E8 25 05 00 00 8B 45 FC }
        $pattern1 = { 74 12 6A 5B 5A 0F 84 ?? ?? ?? ?? 8B 4D F8 }
        $pattern2 = { 3E C9 ?? ?? 00 07 61 90 }

    condition:
        any of them
}