rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 43 1C 00 E8 EE 82 FF FF }
        $pattern1 = { 83 F8 01 74 12 85 C0 74 0E }
        $pattern2 = { 55 8B EC B9 F8 26 43 00 E8 B7 F7 FF FF }

    condition:
        any of them
}