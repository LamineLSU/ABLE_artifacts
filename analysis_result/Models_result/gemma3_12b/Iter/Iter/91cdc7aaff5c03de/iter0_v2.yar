rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 A8 5A 45 00 57 53 53 8D 4D 84 }
        $pattern1 = { 8D 4D E4 51 50 8D 4D E4 51 50 8D 4D E4 }
        $pattern2 = { 84 C0 74 24 57 53 53 8D 4D 84 }

    condition:
        any of them
}