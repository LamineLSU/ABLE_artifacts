rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B 5B E8 25 05 00 00 }
        $pattern1 = { 8B CE E8 74 FA FF FF }
        $pattern2 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF }

    condition:
        any of them
}