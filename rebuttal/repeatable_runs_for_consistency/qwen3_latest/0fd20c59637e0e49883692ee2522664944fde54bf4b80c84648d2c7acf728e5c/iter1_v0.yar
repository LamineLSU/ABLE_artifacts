rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 10 ?? ?? }  // Test EAX, JE (4 bytes + 2 wildcards)
        $pattern1 = { FF 15 ?? ?? ?? ?? }  // Call instruction (6 bytes)
        $pattern2 = { 6A 00 FF 15 ?? ?? ?? ?? }  // Push 0, Call (8 bytes)

    condition:
        any of them
}