rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules targeting specific address ranges"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? 6A 5B 8B CE E8 ?? 74 07 8D 85 00 00 }
        $pattern1 = { 6A 5B 8B CE E8 ?? FF 2C 03 80 8B 4F ?? ?? 0F 84 85 00 00 }
        $pattern2 = { 6A 5B 8B CE E8 ?? FF C1 FA F8 FE FF 00 11 40 8D 3E 70 }

    condition:
        any of them
}