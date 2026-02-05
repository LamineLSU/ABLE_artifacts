rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 40 68 ?? 5A 8B CD 3D 00 00 ?? 74 20 75 10 FF 75 08 E8 CD 3D 00 00 }
        $pattern1 = { 8B 40 68 ?? 5A 8B BF 31 E7 04 ?? 75 10 FF 75 08 E8 BF 31 E7 04 }
        $pattern2 = { 8B 40 68 ?? 5A 8B BE 31 E7 04 ?? 75 10 FF 75 08 E8 BE 31 E7 04 }
    condition:
        any of them
}