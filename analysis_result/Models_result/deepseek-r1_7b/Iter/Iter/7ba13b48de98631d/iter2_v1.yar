rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 64 85 C0 74 12 ?? ?? }
        $pattern1 = { 64 E8 25 89 9D F0 FE FF FF }
        $pattern2 = { 64 03 C9 FF FF A0 00 00 5B }
    condition:
        any of them
}