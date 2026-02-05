rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 CD 3D 00 00 83 F8 01 74 20 }
        $pattern1 = { 8B FF 55 8B EC E8 CD 3D 00 00 83 F8 01 74 20 64 A1 30 00 00 00 }
        $pattern2 = { 8B FF 55 8B EC E8 CD 3D 00 00 83 F8 01 74 20 FF 75 08 E8 6A 30 5A 04 }

    condition:
        any of them
}