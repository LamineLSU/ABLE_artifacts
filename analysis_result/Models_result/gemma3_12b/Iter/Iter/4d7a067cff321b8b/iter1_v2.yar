rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }
        $pattern1 = { 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { E8 4B 17 00 00 A1 88 85 2E 01 }

    condition:
        any of them
}