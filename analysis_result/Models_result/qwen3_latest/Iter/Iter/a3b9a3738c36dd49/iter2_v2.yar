rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 } // Test/jump + call sequence
        $pattern1 = { 85 C0 0F 84 33 FD FF FF } // Test/jump with offset
        $pattern2 = { 85 C0 74 07 50 FF 15 88 A0 39 00 } // Test/jump + exit call

    condition:
        any of them
}