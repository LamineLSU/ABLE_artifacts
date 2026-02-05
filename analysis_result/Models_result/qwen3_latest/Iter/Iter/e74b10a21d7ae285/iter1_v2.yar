rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B } // Test eax, je + stack setup
        $pattern1 = { FF 15 88 A0 0B 00 } // CloseHandle API call (offsets wildcards)
        $pattern2 = { A1 88 85 0B 00 85 C0 } // Memory read + test eax sequence

    condition:
        any of them
}