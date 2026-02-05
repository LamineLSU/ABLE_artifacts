rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 6A 5B } // test eax, eax + je + push
        $pattern1 = { 0F 84 33 FD FF FF } // je with specific offset
        $pattern2 = { E8 E3 FA FF FF 8B 0D 00 00 00 00 } // call + mov (function validation)

    condition:
        any of them
}