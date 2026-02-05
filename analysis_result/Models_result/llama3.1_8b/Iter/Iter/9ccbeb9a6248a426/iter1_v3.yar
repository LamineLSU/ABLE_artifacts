rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE E8 ?? ?? ?? ?? 85 C0 74 ?? }
        $pattern1 = { 8A 04 24 FF D0 5F 5E 83 CD 40 }
        $pattern2 = { B9 01 00 00 00 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}