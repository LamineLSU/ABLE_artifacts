rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 36 34 01 00 }
        $pattern1 = { 55 8B EC 83 EC 18 53 56 57 E8 0E F6 FF FF }
        $pattern2 = { 55 8B EC 83 EC 58 53 56 57 E8 09 00 00 00 }

    condition:
        any of them
}