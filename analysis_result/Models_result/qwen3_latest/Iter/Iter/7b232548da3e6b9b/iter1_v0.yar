rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B } // Test EAX/je + push (early evasion check)
        $pattern1 = { FF 15 ?? ?? ?? ?? } // Call to memory address (exit decision point)
        $pattern2 = { 6A 5B E8 ?? ?? ?? ?? } // Push + call (obfuscation sequence)

    condition:
        any of them
}