rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 56 8B 48 14 6A 35 6A 00 }
        $pattern1 = { 8B 88 BC 00 00 00 56 6A 36 6A 00 }
        $pattern3 = { 51 8D B0 A0 A0 56 }

    condition:
        any of them
}