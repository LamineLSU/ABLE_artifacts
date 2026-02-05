rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern1 = { 33 FF 8B C7 EB 03 8D 43 01 FF 15 ?? ?? ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}