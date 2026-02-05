rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? }
        $pattern1 = { 85 C0 74 12 6A 5B 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern2 = { FF 75 08 FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}