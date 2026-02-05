rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection using FFD2 calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 41 A6 5D FF D2 ?? }
        $pattern1 = { 00 41 A6 7C FF D2 ?? }
        $pattern2 = { 00 41 A6 B5 FF D2 ?? }

    condition:
        any()
}