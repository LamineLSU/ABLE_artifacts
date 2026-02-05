rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 ?? ?? ?? ?? 57 ?? ?? ?? }
        $pattern1 = { 84 C0 ?? ?? 64 A1 30 00 00 00 ?? ?? C1 E8 08 A8 01 }
        $pattern2 = { 6A F4 ?? FF 15 40 30 FB 00 68 10 27 00 00 FF 15 A0 30 FB 00 }

    condition:
        any of them
}