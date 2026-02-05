rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 20 }
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 }
        $pattern2 = { 8B 45 FC 50 FF 15 44 30 2E 01 }

    condition:
        any of them
}