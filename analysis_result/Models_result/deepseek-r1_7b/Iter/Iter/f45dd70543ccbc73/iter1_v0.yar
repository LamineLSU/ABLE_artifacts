rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? 0C 33 ?? }
        $pattern1 = { 6A 5B ?? 5A ?? 0F 84 ?? 74 12 }
        $pattern2 = { BA 21 05 00 ?? FF 0D 03 C3 00 }

    condition:
        any of them
}