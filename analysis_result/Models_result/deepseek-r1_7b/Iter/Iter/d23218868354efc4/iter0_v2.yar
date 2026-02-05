rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 5A 8B CE E8 25 05 00 ?? ?? ?? ?? }
        $pattern1 = { 8D 95 F0 FF FF ?? ?? ?? ?? 8D 43 01 ?? ?? ?? }
        $pattern2 = { E8 C8 FF FF FF ?? ?? ?? ?? ?? ?? ?? }
    condition:
        any of them
}