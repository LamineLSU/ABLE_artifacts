rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 36 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 8B 45 08 8B 88 18 0A 00 8B 4D 0C }
        $pattern2 = { 8B 06 50 51 FF D2 }

    condition:
        any of them
}