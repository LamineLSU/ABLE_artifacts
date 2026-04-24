rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD FF FF 50 FF 15 2C A1 F9 00 }
        $pattern1 = { 85 C0 0F 84 33 FD FF FF 50 FF 15 2C A1 F6 00 }
        $pattern2 = { 85 C0 0F 84 33 FD FF FF 50 FF 15 2C A1 82 00 }

    condition:
        any of them
}