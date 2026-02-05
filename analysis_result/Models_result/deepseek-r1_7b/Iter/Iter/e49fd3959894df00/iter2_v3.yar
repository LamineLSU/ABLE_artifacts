rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 75 07 ?? 43 FC }
        $pattern1 = { 89 85 A8 FE FF FF 5B 0F 8A FE FF 5E 02 }
        $pattern2 = { 89 B5 8C 85 C0 75 07 ?? FC }

    condition:
        any of them
}