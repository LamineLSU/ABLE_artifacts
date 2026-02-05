rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 ?? ?? ?? ?? 00 00 00 0E }
        $pattern2 = { 85 C0 E8 4B 00 00 01 0E 74 07 8B 45 FC }
    condition:
        any of them
}