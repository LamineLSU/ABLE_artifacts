rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 F7 25 00 00 83 F8 01 74 20 64 A1 30 00 00 00 8B 40 68 }
        $pattern1 = { 8B FF 55 8B EC E8 F7 25 00 00 83 F8 01 74 0C 6A 01 5A 8B CE }
        $pattern2 = { 8B FF 55 8B EC E8 F7 25 00 00 83 F8 01 74 1A 6A 02 5A 8B CE }

    condition:
        any of them
}