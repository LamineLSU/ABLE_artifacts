rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 5A 5B 8B CE E8 ?? ?? ?? ?? 25 05 00 }
        $pattern1 = { 8B FF 5A 5B 8B CE E8 43 01 05 00 }
        $pattern2 = { 8B FF 5A 5B 8B CE E8 96 03 00 }

    condition:
        any of them
}