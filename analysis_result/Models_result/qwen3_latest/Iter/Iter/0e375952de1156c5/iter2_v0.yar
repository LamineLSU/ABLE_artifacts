rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B 45 FC }  // Test eax, je + mov (specific stack offset)
        $pattern1 = { FF 15 2C A1 0C 00 }      // Call to ExitProcess (exact bytes)
        $pattern2 = { 85 C0 0F 84 33 FD FF FF } // Test eax, je with offset (specific address)

    condition:
        any of them
}