rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? E8 CD 3D 00 00 }
        $pattern2 = { 6A ?? 5A 8B CE E8 12 35 81 04 }
        $pattern3 = { C1 E8 08 A8 01 75 10 FF 75 08 E8 94 DB 13 75 }

    condition:
        any of them
}