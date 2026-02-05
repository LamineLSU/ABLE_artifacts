rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 48 83 EC 20 E8 27 00 00 00 ?? ?? }
        $pattern1 = { 8B D9 E8 27 00 00 00 84 C0 ?? }
        $pattern2 = { FF 15 A9 16 01 00 FF 15 1E 17 01 00 8B CB }

    condition:
        any of them
}