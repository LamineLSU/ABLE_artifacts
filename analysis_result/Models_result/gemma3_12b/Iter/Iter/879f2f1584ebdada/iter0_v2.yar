rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 85 F0 FE FF FF 8B 8D 95 F0 FE FF FF 89 9D F0 FE FF FF }
        $pattern1 = { 8B CE E8 74 FA FF FF 85 C0 0F 84 33 FD FF FF }
        $pattern2 = { FF 15 2C A1 B5 00 33 FF 8B 47 04 5F 5E 33 CD }

    condition:
        any of them
}