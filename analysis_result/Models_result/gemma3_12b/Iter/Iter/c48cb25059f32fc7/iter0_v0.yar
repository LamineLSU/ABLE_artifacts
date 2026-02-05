rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 85 94 FD FF FF 8B 85 94 FD FF FF }
        $pattern1 = { 50 A1 64 B5 41 00 8B 00 FF D0 }
        $pattern2 = { 8D 85 78 FD FF FF 8D 95 78 FD FF FF }

    condition:
        any of them
}