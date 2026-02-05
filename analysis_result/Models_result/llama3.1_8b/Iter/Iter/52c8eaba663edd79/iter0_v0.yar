rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 85 C0 }
        $pattern1 = { 89 DF F0 FE FF 8B CE E8 74 FA FF E8 73 FC FF }
        $pattern2 = { FF 15 2C A1 AF 00 53 FF 15 2C CA 1A 00 }

    condition:
        any of them
}