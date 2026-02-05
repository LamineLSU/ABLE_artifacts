rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 84 94 45 00 8B 45 ?? 33 CD } // Trace 1, 0x41569B
        $pattern1 = { FF 15 84 94 45 00 83 C4 18 53 } // Trace 3, 0x425F49
        $pattern2 = { FF 15 84 94 45 00 8B 0D 38 91 45 } // Trace 4, 0x41569B

    condition:
        any of them
}