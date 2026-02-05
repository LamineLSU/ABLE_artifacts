rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC B9 F8 26 43 00 E8 3C 01 00 00 E8 EE 82 FF }
        $pattern1 = { 85 C0 74 0E E8 E0 A2 FF FF }
        $pattern2 = { 6A 00 5A 8B CE E8 B7 F7 FF }

    condition:
        any of them
}