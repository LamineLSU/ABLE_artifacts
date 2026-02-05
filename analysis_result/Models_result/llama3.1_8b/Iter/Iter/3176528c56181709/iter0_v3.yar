rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp2=$pattern3+0,action2=skip,bp3=$pattern2+0,action3=skip,count=0"

    strings:
        $pattern1 = { 6B ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { C3 8B 45 ?? 8B 45 10 }
        $pattern3 = { 8B 16 50 51 FF D2 }

    condition:
        any of them
}