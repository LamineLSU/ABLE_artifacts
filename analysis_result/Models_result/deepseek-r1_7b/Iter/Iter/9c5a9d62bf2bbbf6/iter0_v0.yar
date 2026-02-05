rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting memory addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF }
        $pattern1 = { 85 C0 FF 8B 4D E8 4B 17 00 00 }
        $pattern2 = { 6A 40 53 E8 E3 FA FF FF E9 B5 FC FF FF }

    condition:
        any of them
}