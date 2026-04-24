rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 0F 84 33 FD FF FF 85 C0 ?? ?? ?? }
        $pattern1 = { E8 4B 17 00 00 50 E8 E3 FA FF FF FF 15 AC B0 41 00 }
        $pattern2 = { FF 75 08 59 FF 75 08 FF 15 AC B0 41 00 }

    condition:
        any of them
}