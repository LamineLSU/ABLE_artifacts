rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 56 E8 ?? ?? ?? ?? 8B 45 }
        $pattern1 = { 6A 36 51 8D B0 A0 0C 00 00 }

    condition:
        any of them
}