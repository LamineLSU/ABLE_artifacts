rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 64 A1 30 00 00 00 85 C0 74 ?? 8B 45 }
        $pattern1 = { C1 E8 08 E8 B7 B2 ?? ?? ?? 6A }
        $pattern2 = { 8B 40 68 FF D5 75 F4 8B CE E8 ?? ?? ?? }

    condition:
        any of them
}