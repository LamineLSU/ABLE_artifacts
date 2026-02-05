rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }
        $pattern1 = { 8B 85 F0 FE FF FF 8D 8D F8 FE FF FF }
        $pattern2 = { 50 E8 E3 FA FF FF }

    condition:
        any of them
}