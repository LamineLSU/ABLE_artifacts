rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? 5A 8B CE E8 FF ?? ?? ?? ?? 74 12 ?? }
        $pattern1 = { 6A 5B 5A 8B CE E8 FF ?? ?? ?? ?? 74 15 0F 84 ?? }
        $pattern2 = { 53 53 BA 21 0D 00 00 8B E5 FF 15 2C A1 95 00 C3 00 95 6E 2C ?? }

    condition:
        any of them
}