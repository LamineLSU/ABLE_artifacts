rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? ?? ?? 8B CE E8 ?? ?? ?? ?? }
        $pattern1 = { 6A 5B 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 0F BE C9 8B 45 FC 83 EC ?? 56 FF D2 }

    condition:
        any of them
}