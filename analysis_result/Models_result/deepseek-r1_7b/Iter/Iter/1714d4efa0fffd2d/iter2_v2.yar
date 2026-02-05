rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific exit decision sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 FF 84 33 FD FF FF 8B CE E8 B3 03 00 00 }
        $pattern1 = { 85 C0 74 12 FF 84 33 FD FF FF 8B CE E9 B5 FC FF FF }
        $pattern2 = { 85 C0 74 12 FF 84 33 FD FF FF 8B CE E8 25 05 00 00 }

    condition:
        any of them
}