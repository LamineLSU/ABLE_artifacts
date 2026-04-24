rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 5A 8B CE E8 25 05 00 00 85 C0 }
        $pattern1 = { 6A 40 53 6A 40 53 68 40 11 0E 01 33 C9 E8 4B 17 00 00 }
        $pattern2 = { 50 53 FF 15 88 A0 0E 01 01 0E 61 F8 FF 15 2C A1 0E 01 }

    condition:
        any of them
}