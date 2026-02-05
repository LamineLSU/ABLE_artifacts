rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 66 81 3C 24 E4 07 ?? ?? ?? ?? 83 C4 10 }
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 66 81 3C 24 E4 07 }

    condition:
        any of them
}