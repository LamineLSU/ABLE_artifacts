rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific early test and jump"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE 00 82 }
        $pattern1 = { 85 C0 0F 84 33 FD FF FF 74 07 0F 84 33 FD FF FF }
        $pattern2 = { 08 3E 6A 41 53 00 00 0F 97 00 FF 00 00 00 00 }

    condition:
        (any of them)
}